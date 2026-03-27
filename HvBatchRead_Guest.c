/**
 * @file HvBatchRead_Guest.c
 * @brief Guest 侧批量散射读取实现 (DBKKernel 项目)
 *
 * ═══════════════════════════════════════════════════════════════════════
 * 添加到 DBKKernel 项目。需要在以下地方集成:
 *
 * 1. IOPLDispatcher.h 添加:
 *    #define IOCTL_CE_BATCH_READ CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0860,
 *            METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
 *
 * 2. IOPLDispatcher.c 的 DispatchIoctl switch 中添加:
 *    case IOCTL_CE_BATCH_READ:
 *        ntStatus = HvBatchRead_HandleIoctl(Irp, ...);
 *        break;
 *
 * 3. HvBridge_Init() 后调用 HvBatchRead_Init()
 * 4. HvBridge_Cleanup() 前调用 HvBatchRead_Cleanup()
 * ═══════════════════════════════════════════════════════════════════════
 */

#include "HvBatchRead.h"
#include "HvMemBridge.h"
#include <intrin.h>

 /* CPUID leaf for batch read VMEXIT */
#ifndef CPUID_HV_BATCH_READ
#define CPUID_HV_BATCH_READ  0x41414151
#endif

/* [BUG FIX] ASM helper: sets RBX = context PA before CPUID
 * __cpuidex does NOT set RBX, causing VMM to read garbage context PA.
 * See dbkfunca.asm for implementation. */
extern void HvCpuidWithRbx(int leaf, int subleaf, UINT64 rbxValue, int* regs);

/* 前向声明 */
void HvBatchRead_Cleanup(void);

/* ========================================================================
 * 全局状态
 * ======================================================================== */

static PHV_BATCH_CONTEXT g_BatchContext = NULL;
static ULONG64           g_BatchContextPa = 0;
static BOOLEAN           g_BatchInitialized = FALSE;

/* 预分配散射表 (避免每次扫描时分配) */
static PHV_SCATTER_ENTRY g_ScatterTable = NULL;
static ULONG64           g_ScatterTablePa = 0;

/* 预分配输出缓冲区 (物理连续, 最大 4MB) */
static PVOID   g_OutputBuffer = NULL;
static ULONG64 g_OutputBufferPa = 0;
static ULONG32 g_OutputBufferSize = 0;

/* 同步锁 (一次只能有一个批量读取操作) */
static FAST_MUTEX g_BatchMutex;

/* ========================================================================
 * 初始化 / 清理
 * ======================================================================== */

 /**
  * @brief 初始化批量读取引擎
  *
  * 预分配所有物理连续缓冲区, 避免扫描时的内存分配开销。
  * 预分配大小:
  *   BatchContext: 1 PAGE = 4KB
  *   ScatterTable: 512 × 24 = ~12KB → 4 pages = 16KB
  *   OutputBuffer: 2MB (可配置)
  */
NTSTATUS HvBatchRead_Init(void)
{
    PHYSICAL_ADDRESS highAddr;
    highAddr.QuadPart = ~0ULL;

    if (g_BatchInitialized) return STATUS_SUCCESS;

    ExInitializeFastMutex(&g_BatchMutex);

    /* 1. BatchContext */
    g_BatchContext = (PHV_BATCH_CONTEXT)MmAllocateContiguousMemory(PAGE_SIZE, highAddr);
    if (!g_BatchContext) goto fail;
    RtlZeroMemory(g_BatchContext, PAGE_SIZE);
    g_BatchContextPa = MmGetPhysicalAddress(g_BatchContext).QuadPart;

    /* 2. ScatterTable (512 entries x 24 bytes = 12KB, 分配 16KB 对齐) */
    g_ScatterTable = (PHV_SCATTER_ENTRY)MmAllocateContiguousMemory(
        HV_BATCH_MAX_ENTRIES * sizeof(HV_SCATTER_ENTRY), highAddr);
    if (!g_ScatterTable) goto fail;
    RtlZeroMemory(g_ScatterTable, HV_BATCH_MAX_ENTRIES * sizeof(HV_SCATTER_ENTRY));
    g_ScatterTablePa = MmGetPhysicalAddress(g_ScatterTable).QuadPart;

    /* 3. OutputBuffer (预分配 2MB, 平衡内存占用和批量大小) */
    g_OutputBufferSize = 2 * 1024 * 1024;
    g_OutputBuffer = MmAllocateContiguousMemory(g_OutputBufferSize, highAddr);
    if (!g_OutputBuffer) goto fail;
    g_OutputBufferPa = MmGetPhysicalAddress(g_OutputBuffer).QuadPart;

    DbgPrint("[BatchRead] Init OK: ctx=0x%llX scatter=0x%llX output=0x%llX (%uKB)\n",
        g_BatchContextPa, g_ScatterTablePa, g_OutputBufferPa,
        g_OutputBufferSize / 1024);

    g_BatchInitialized = TRUE;
    return STATUS_SUCCESS;

fail:
    HvBatchRead_Cleanup();
    DbgPrint("[BatchRead] Init FAILED: insufficient contiguous memory\n");
    return STATUS_INSUFFICIENT_RESOURCES;
}

void HvBatchRead_Cleanup(void)
{
    g_BatchInitialized = FALSE;
    KeMemoryBarrier();

    ExAcquireFastMutex(&g_BatchMutex);

    if (g_OutputBuffer) { MmFreeContiguousMemory(g_OutputBuffer);  g_OutputBuffer = NULL; }
    if (g_ScatterTable) { MmFreeContiguousMemory(g_ScatterTable);  g_ScatterTable = NULL; }
    if (g_BatchContext) { MmFreeContiguousMemory(g_BatchContext);  g_BatchContext = NULL; }

    ExReleaseFastMutex(&g_BatchMutex);
}

/* ========================================================================
 * 获取进程 CR3
 * ======================================================================== */

static ULONG64 BatchGetCr3(ULONG64 pid)
{
    PEPROCESS proc = NULL;
    ULONG64 cr3;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(
        (PVOID)(UINT_PTR)pid, &proc)) || !proc)
        return 0;

    cr3 = *(PULONG64)((PUCHAR)proc + 0x28) & 0x000FFFFFFFFFF000ULL;

    ObDereferenceObject(proc);
    return cr3;
}

/* ========================================================================
 * 核心: 执行批量读取
 *
 * [FIX v2] 修复两个导致 Next Scan 结果锐减的 bug:
 *
 *   Bug 1 — __try/__except 作用域过大
 *     旧代码: __try 包裹整个 for 循环。如果 entry[3] 的某页是
 *     PAGE_NOACCESS, 异常被捕获后 entry[4]~entry[count-1] 全部
 *     不会被触摸。VMM 读这些页面 PTE.Present=0 → 输出零。
 *     修复: __try/__except 改为逐页粒度。
 *
 *   Bug 2 — 触摸和 CPUID 之间有时间窗口
 *     旧代码: attach → 触摸 → detach → 填 context → CPUID
 *     detach 后 Windows 随时可将刚触摸的页面从工作集修剪。
 *     修复: attach → 触摸 → 填 context → CPUID → detach
 * ======================================================================== */
static NTSTATUS DoBatchRead(
    ULONG64          pid,
    PBATCH_READ_ENTRY entries,
    ULONG32          count,
    PVOID            output,
    ULONG32          outputSize,
    PULONG32         pSuccess)
{
    ULONG64 cr3;
    ULONG32 totalDataSize = 0;
    PEPROCESS targetProc = NULL;
    KAPC_STATE apc;

    *pSuccess = 0;

    if (!g_BatchInitialized)
        return STATUS_DEVICE_NOT_READY;

    if (count == 0 || count > HV_BATCH_MAX_ENTRIES) return STATUS_INVALID_PARAMETER;

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

    /* 清零输出缓冲区 — VMM 跳过的页面保持为零 */
    RtlZeroMemory(g_OutputBuffer, totalDataSize);

    /* 获取 CR3 */
    cr3 = BatchGetCr3(pid);
    if (!cr3) return STATUS_NOT_FOUND;

    /* 获取 EPROCESS */
    if (!NT_SUCCESS(PsLookupProcessByProcessId(
        (PVOID)(UINT_PTR)pid, &targetProc)) || !targetProc)
        return STATUS_NOT_FOUND;

    /* ================================================================
     * 关键区间: attach → 触摸 → CPUID → detach
     * 整个过程在目标进程地址空间中, 页面保持 present
     * ================================================================ */
    KeStackAttachProcess(targetProc, &apc);

    /* 逐页触摸确保页面 present */
    {
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
                SIZE_T pageRem = PAGE_SIZE - (((ULONG_PTR)(base + off)) & 0xFFF);
                off += pageRem;
            }
        }
    }

    /* 填充 BatchContext (仍然 attached) */
    RtlZeroMemory(g_BatchContext, sizeof(HV_BATCH_CONTEXT));
    g_BatchContext->TargetCr3 = cr3;
    g_BatchContext->EntryCount = count;
    g_BatchContext->TotalOutputSize = totalDataSize;
    g_BatchContext->EntriesPa = g_ScatterTablePa;
    g_BatchContext->OutputPa = g_OutputBufferPa;
    g_BatchContext->Status = 1; /* Pending */

    KeMemoryBarrier();

    /* CPUID VMEXIT — RBX 传递 BatchContext PA
     * VMM 侧 HvHandleBatchRead 用 VmxMapPhys 无锁映射处理 */
    {
        int regs[4] = { 0 };
        HvCpuidWithRbx(CPUID_HV_BATCH_READ, 0, g_BatchContextPa, regs);
    }

    /* detach */
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(targetProc);

    *pSuccess = g_BatchContext->SuccessCount;

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
 * 单次 VMEXIT 读取 — 供 IOCTL_CE_READMEMORY 使用
 * ======================================================================== */

BOOLEAN HvBatchRead_SingleRead(ULONG64 pid, ULONG64 address, PVOID output, ULONG32 size)
{
    BATCH_READ_ENTRY entry;
    ULONG32 success = 0;
    NTSTATUS status;

    if (!g_BatchInitialized) {
        HvBatchRead_Init();  /* best-effort lazy init */
    }
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