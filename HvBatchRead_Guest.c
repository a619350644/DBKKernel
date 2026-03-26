/**
 * @file HvBatchRead_Guest.c
 * @brief Guest 侧批量散射读取实现 (DBKKernel 项目)
 *
 * 实现方式: KeStackAttachProcess → 逐页触摸 → 直接 RtlCopyMemory
 * 不经过 VMEXIT, 不调用 MmCopyVirtualMemory (不触发 hook)
 *
 * ═══════════════════════════════════════════════════════════════════════
 * 集成步骤:
 * 1. IOPLDispatcher.h: #define IOCTL_CE_BATCH_READ
 * 2. IOPLDispatcher.c: case IOCTL_CE_BATCH_READ → HvBatchRead_Dispatch
 * 3. 驱动加载后调用 HvBatchRead_Init() (或依赖 lazy init)
 * 4. 驱动卸载前调用 HvBatchRead_Cleanup()
 * ═══════════════════════════════════════════════════════════════════════
 */

#include "HvBatchRead.h"
#include "HvMemBridge.h"

 /* 前向声明 */
void HvBatchRead_Cleanup(void);

/* ========================================================================
 * 全局状态
 * ======================================================================== */

static BOOLEAN           g_BatchInitialized = FALSE;
static PHV_SCATTER_ENTRY g_ScatterTable = NULL;
static PVOID             g_OutputBuffer = NULL;
static ULONG32           g_OutputBufferSize = 0;
static FAST_MUTEX        g_BatchMutex;

/* ========================================================================
 * 初始化 / 清理
 * ======================================================================== */

NTSTATUS HvBatchRead_Init(void)
{
    PHYSICAL_ADDRESS highAddr;
    highAddr.QuadPart = ~0ULL;

    if (g_BatchInitialized) return STATUS_SUCCESS;

    ExInitializeFastMutex(&g_BatchMutex);

    g_ScatterTable = (PHV_SCATTER_ENTRY)MmAllocateContiguousMemory(
        HV_BATCH_MAX_ENTRIES * sizeof(HV_SCATTER_ENTRY), highAddr);
    if (!g_ScatterTable) goto fail;
    RtlZeroMemory(g_ScatterTable, HV_BATCH_MAX_ENTRIES * sizeof(HV_SCATTER_ENTRY));

    g_OutputBufferSize = 2 * 1024 * 1024;
    g_OutputBuffer = MmAllocateContiguousMemory(g_OutputBufferSize, highAddr);
    if (!g_OutputBuffer) goto fail;

    g_BatchInitialized = TRUE;
    return STATUS_SUCCESS;

fail:
    HvBatchRead_Cleanup();
    return STATUS_INSUFFICIENT_RESOURCES;
}

void HvBatchRead_Cleanup(void)
{
    g_BatchInitialized = FALSE;
    KeMemoryBarrier();

    ExAcquireFastMutex(&g_BatchMutex);

    if (g_OutputBuffer) { MmFreeContiguousMemory(g_OutputBuffer);  g_OutputBuffer = NULL; }
    if (g_ScatterTable) { MmFreeContiguousMemory(g_ScatterTable);  g_ScatterTable = NULL; }

    ExReleaseFastMutex(&g_BatchMutex);
}

/* ========================================================================
 * 核心: 执行批量读取
 *
 * attach → 逐页触摸 → 直接 memcpy → detach
 * ======================================================================== */
static NTSTATUS DoBatchRead(
    ULONG64          pid,
    PBATCH_READ_ENTRY entries,
    ULONG32          count,
    PVOID            output,
    ULONG32          outputSize,
    PULONG32         pSuccess)
{
    ULONG32 totalDataSize = 0;
    PEPROCESS targetProc = NULL;
    KAPC_STATE apc;

    *pSuccess = 0;

    if (!g_BatchInitialized)
        return STATUS_DEVICE_NOT_READY;

    if (count == 0 || count > HV_BATCH_MAX_ENTRIES)
        return STATUS_INVALID_PARAMETER;

    /* 填充散射表 + 计算总输出大小 */
    for (ULONG32 i = 0; i < count; i++) {
        if (entries[i].Size == 0 || entries[i].Size > PAGE_SIZE)
            return STATUS_INVALID_PARAMETER;

        g_ScatterTable[i].GuestVa = entries[i].Address;
        g_ScatterTable[i].Size = entries[i].Size;
        g_ScatterTable[i].OutputOffset = totalDataSize;
        g_ScatterTable[i].Status = 0xFFFFFFFF;
        g_ScatterTable[i].Reserved = 0;

        totalDataSize += entries[i].Size;
    }

    if (totalDataSize > g_OutputBufferSize || totalDataSize > outputSize)
        return STATUS_BUFFER_TOO_SMALL;

    RtlZeroMemory(g_OutputBuffer, totalDataSize);

    if (!NT_SUCCESS(PsLookupProcessByProcessId(
        (PVOID)(UINT_PTR)pid, &targetProc)) || !targetProc)
        return STATUS_NOT_FOUND;

    /* attach 到目标进程 */
    KeStackAttachProcess(targetProc, &apc);

    /* 逐页触摸, 确保页面 present */
    for (ULONG32 i = 0; i < count; i++) {
        PUCHAR base = (PUCHAR)(ULONG_PTR)entries[i].Address;
        ULONG32 size = entries[i].Size;
        SIZE_T off = 0;
        while (off < size) {
            __try {
                volatile UCHAR dummy = *(volatile UCHAR*)(base + off);
                (void)dummy;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            off += PAGE_SIZE - (((ULONG_PTR)(base + off)) & 0xFFF);
        }
    }

    /* 直接读取 */
    {
        ULONG32 successCount = 0;

        for (ULONG32 i = 0; i < count; i++) {
            PUCHAR srcAddr = (PUCHAR)(ULONG_PTR)entries[i].Address;
            ULONG32 readSize = entries[i].Size;
            ULONG32 outOffset = g_ScatterTable[i].OutputOffset;

            __try {
                RtlCopyMemory(
                    (PUCHAR)g_OutputBuffer + outOffset,
                    srcAddr,
                    readSize);
                successCount++;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        *pSuccess = successCount;
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(targetProc);

    if (*pSuccess > 0) {
        __try {
            RtlCopyMemory(output, g_OutputBuffer, totalDataSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

/* ========================================================================
 * 单次读取
 * ======================================================================== */

BOOLEAN HvBatchRead_SingleRead(ULONG64 pid, ULONG64 address, PVOID output, ULONG32 size)
{
    BATCH_READ_ENTRY entry;
    ULONG32 success = 0;
    NTSTATUS status;

    if (!g_BatchInitialized)
        HvBatchRead_Init();

    if (!g_BatchInitialized || size == 0 || size > PAGE_SIZE || !output)
        return FALSE;

    entry.Address = address;
    entry.Size = size;

    ExAcquireFastMutex(&g_BatchMutex);
    status = DoBatchRead(pid, &entry, 1, output, size, &success);
    ExReleaseFastMutex(&g_BatchMutex);

    return NT_SUCCESS(status) && success > 0;
}

/* ========================================================================
 * IOCTL 处理器
 * ======================================================================== */

NTSTATUS HvBatchRead_Dispatch(
    PVOID       SystemBuffer,
    ULONG       InputLength,
    ULONG       OutputLength,
    PULONG_PTR  BytesReturned)
{
    NTSTATUS status;
    PBATCH_READ_INPUT inp;
    PBATCH_READ_ENTRY entries;
    ULONG32 count;
    ULONG32 headerSize;
    ULONG32 totalDataSize;
    ULONG32 successCount = 0;

    *BytesReturned = 0;

    /* Lazy init */
    if (!g_BatchInitialized) {
        NTSTATUS initSt = HvBatchRead_Init();
        if (!NT_SUCCESS(initSt))
            return initSt;
    }

    if (!SystemBuffer)
        return STATUS_INVALID_PARAMETER;

    if (InputLength < sizeof(BATCH_READ_INPUT))
        return STATUS_BUFFER_TOO_SMALL;

    inp = (PBATCH_READ_INPUT)SystemBuffer;
    count = inp->Count;

    if (count == 0 || count > HV_BATCH_MAX_ENTRIES)
        return STATUS_INVALID_PARAMETER;

    headerSize = sizeof(BATCH_READ_INPUT);
    if (InputLength < headerSize + count * sizeof(BATCH_READ_ENTRY))
        return STATUS_BUFFER_TOO_SMALL;

    entries = (PBATCH_READ_ENTRY)((PUCHAR)SystemBuffer + headerSize);

    totalDataSize = 0;
    for (ULONG32 i = 0; i < count; i++) {
        if (entries[i].Size > PAGE_SIZE) return STATUS_INVALID_PARAMETER;
        totalDataSize += entries[i].Size;
    }

    if (OutputLength < sizeof(BATCH_READ_OUTPUT) + totalDataSize)
        return STATUS_BUFFER_TOO_SMALL;

    ExAcquireFastMutex(&g_BatchMutex);

    status = DoBatchRead(
        inp->ProcessID,
        entries,
        count,
        (PUCHAR)SystemBuffer + sizeof(BATCH_READ_OUTPUT),
        OutputLength - sizeof(BATCH_READ_OUTPUT),
        &successCount);

    ExReleaseFastMutex(&g_BatchMutex);

    if (NT_SUCCESS(status)) {
        PBATCH_READ_OUTPUT outp = (PBATCH_READ_OUTPUT)SystemBuffer;
        outp->SuccessCount = successCount;
        outp->TotalSize = totalDataSize;
        *BytesReturned = sizeof(BATCH_READ_OUTPUT) + totalDataSize;
    }

    return status;
}