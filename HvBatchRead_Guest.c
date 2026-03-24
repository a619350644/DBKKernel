/**
 * @file HvBatchRead_Guest.c
 * @brief Guest 侧批量散射读取实现 (DBKKernel 项目)
 *
 * ═══════════════════════════════════════════════════════════════════════
 *  添加到 DBKKernel 项目。需要在以下地方集成:
 *
 *  1. IOPLDispatcher.h 添加:
 *       #define IOCTL_CE_BATCH_READ  CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0860,
 *               METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
 *
 *  2. IOPLDispatcher.c 的 DispatchIoctl switch 中添加:
 *       case IOCTL_CE_BATCH_READ:
 *           ntStatus = HvBatchRead_HandleIoctl(Irp, ...);
 *           break;
 *
 *  3. HvBridge_Init() 后调用 HvBatchRead_Init()
 *  4. HvBridge_Cleanup() 前调用 HvBatchRead_Cleanup()
 * ═══════════════════════════════════════════════════════════════════════
 */

#include "HvBatchRead.h"
#include "HvMemBridge.h"
#include <intrin.h>

 /* [BUG FIX] ASM helper: sets RBX = context PA before CPUID
  * __cpuidex does NOT set RBX, causing VMM to read garbage context PA.
  * See dbkfunca.asm for implementation. */
extern void HvCpuidWithRbx(int leaf, int subleaf, UINT64 rbxValue, int* regs);

/* 前向声明 */
void HvBatchRead_Cleanup(void);

/* ========================================================================
 *  全局状态
 * ======================================================================== */
static PHV_BATCH_CONTEXT g_BatchContext = NULL;
static ULONG64 g_BatchContextPa = 0;
static BOOLEAN g_BatchInitialized = FALSE;

/* 预分配散射表 (避免每次扫描时分配) */
static PHV_SCATTER_ENTRY g_ScatterTable = NULL;
static ULONG64 g_ScatterTablePa = 0;

/* 预分配输出缓冲区 (物理连续, 最大 4MB) */
static PVOID g_OutputBuffer = NULL;
static ULONG64 g_OutputBufferPa = 0;
static ULONG32 g_OutputBufferSize = 0;

/* 同步锁 (一次只能有一个批量读取操作) */
static FAST_MUTEX g_BatchMutex;

/* ========================================================================
 *  初始化 / 清理
 * ======================================================================== */

 /**
  * @brief 初始化批量读取引擎
  *
  * 预分配所有物理连续缓冲区, 避免扫描时的内存分配开销。
  * 预分配大小:
  *   BatchContext: 1 PAGE  = 4KB
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

    /* 2. ScatterTable (512 entries × 24 bytes = 12KB, 分配 16KB 对齐) */
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
    /* ★ 先标记为未初始化, 阻止新的 DoBatchRead 进入 */
    g_BatchInitialized = FALSE;
    KeMemoryBarrier();

    /* 获取锁, 等待正在进行的 DoBatchRead 完成 */
    ExAcquireFastMutex(&g_BatchMutex);

    if (g_OutputBuffer) { MmFreeContiguousMemory(g_OutputBuffer); g_OutputBuffer = NULL; }
    if (g_ScatterTable) { MmFreeContiguousMemory(g_ScatterTable); g_ScatterTable = NULL; }
    if (g_BatchContext) { MmFreeContiguousMemory(g_BatchContext);  g_BatchContext = NULL; }

    ExReleaseFastMutex(&g_BatchMutex);
}

/* ========================================================================
 *  获取进程 CR3
 * ======================================================================== */
static ULONG64 BatchGetCr3(ULONG64 pid)
{
    PEPROCESS proc = NULL;
    ULONG64 cr3;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(
        (PVOID)(UINT_PTR)pid, &proc)) || !proc)
        return 0;

    /* [FIX] 始终使用 DirectoryTableBase (offset 0x28)
     *
     * 原代码优先使用 UserDirectoryTableBase (0x280), 仅 Intel KPTI 时有效。
     * 在 AMD 系统上 KPTI 通常关闭, +0x280 包含无效标志值 (如 0x200001000),
     * 导致 VMM 页表遍历全部失败 (success=0/1)。
     *
     * DirectoryTableBase (+0x28) 无论 KPTI 开关都映射完整地址空间 (用户+内核),
     * 是最可靠的 CR3 来源。 */
    cr3 = *(PULONG64)((PUCHAR)proc + 0x28) & 0x000FFFFFFFFFF000ULL;

    ObDereferenceObject(proc);
    return cr3;
}

/* ========================================================================
 *  核心: 执行批量读取
 *
 *  Guest 侧操作:
 *    1. 填充散射表
 *    2. 填充 BatchContext
 *    3. 发起 CPUID(CPUID_HV_BATCH_READ) — 一次 VMEXIT
 *    4. 返回后, 输出缓冲区已由 VMM 填充
 * ======================================================================== */

 /**
  * @brief 执行一批散射读取
  *
  * @param pid        目标进程 PID
  * @param entries    CE 请求的读取条目数组
  * @param count      条目数 (1 ~ HV_BATCH_MAX_ENTRIES)
  * @param output     [OUT] 读取结果缓冲区 (调用者分配)
  * @param outputSize 输出缓冲区大小
  * @param pSuccess   [OUT] 成功读取的条目数
  * @return STATUS_SUCCESS 或错误码
  */
static NTSTATUS DoBatchRead(
    ULONG64 pid,
    PBATCH_READ_ENTRY entries,
    ULONG32 count,
    PVOID output,
    ULONG32 outputSize,
    PULONG32 pSuccess)
{
    ULONG64 cr3;
    int regs[4] = { 0 };
    ULONG32 totalDataSize = 0;
    static volatile LONG s_batchDiag = 0;

    *pSuccess = 0;

    if (!g_BatchInitialized) {
        LONG dCnt = InterlockedIncrement(&s_batchDiag);
        if (dCnt <= 5) {
            DbgPrint("[BatchRead] NOT INITIALIZED — will fallback! (call #%d)\n", dCnt);
        }
        return STATUS_DEVICE_NOT_READY;
    }
    if (count == 0 || count > HV_BATCH_MAX_ENTRIES) return STATUS_INVALID_PARAMETER;

    /* 计算总输出大小并填充散射表 */
    for (ULONG32 i = 0; i < count; i++) {
        if (entries[i].Size == 0 || entries[i].Size > PAGE_SIZE)
            return STATUS_INVALID_PARAMETER;

        g_ScatterTable[i].GuestVa = entries[i].Address;
        g_ScatterTable[i].Size = entries[i].Size;
        g_ScatterTable[i].OutputOffset = totalDataSize;
        g_ScatterTable[i].Status = 0xFFFFFFFF; /* 未处理 */
        g_ScatterTable[i].Reserved = 0;

        totalDataSize += entries[i].Size;
    }

    if (totalDataSize > g_OutputBufferSize || totalDataSize > outputSize)
        return STATUS_BUFFER_TOO_SMALL;

    /* 获取 CR3 */
    cr3 = BatchGetCr3(pid);
    if (!cr3) return STATUS_NOT_FOUND;

    /* 填充 BatchContext */
    RtlZeroMemory(g_BatchContext, sizeof(HV_BATCH_CONTEXT));
    g_BatchContext->TargetCr3 = cr3;
    g_BatchContext->EntryCount = count;
    g_BatchContext->TotalOutputSize = totalDataSize;
    g_BatchContext->EntriesPa = g_ScatterTablePa;
    g_BatchContext->OutputPa = g_OutputBufferPa;
    g_BatchContext->Status = 1; /* Pending */

    /* 内存屏障: 确保所有写入在 CPUID 前对 VMM 可见 */
    KeMemoryBarrier();

    {
        static volatile LONG s_cpuidTrigger = 0;
        LONG tCnt = InterlockedIncrement(&s_cpuidTrigger);
        if (tCnt <= 10 || (tCnt % 5000) == 0) {
            DbgPrint("[BatchRead] >>> CPUID VMEXIT #%d: leaf=0x%X CR3=0x%llX entries=%u totalSize=%u\n",
                tCnt, CPUID_HV_BATCH_READ, cr3, count, totalDataSize);
        }
    }

    /* ★ 一次 CPUID — 一次 VMEXIT — VMM 读取所有条目 ★
     * [BUG FIX] 使用 HvCpuidWithRbx 设置 RBX = g_BatchContextPa
     * 旧代码 __cpuidex 不设置 RBX, VMM 读到的 RBX 是垃圾值
     * 导致 VMM 映射错误的物理地址, batch read 全部失败 */
    HvCpuidWithRbx(CPUID_HV_BATCH_READ, 0, g_BatchContextPa, regs);

    /* VMRUN 返回, 输出缓冲区已填充 */
    if (g_BatchContext->Status > 0) {
        /* VMM 未处理 (可能 Hypervisor 不支持 CPUID_HV_BATCH_READ) */
        static volatile LONG s_notSupported = 0;
        LONG nsCnt = InterlockedIncrement(&s_notSupported);
        if (nsCnt <= 10) {
            DbgPrint("[BatchRead] !!! VMM NOT SUPPORTED: Status=%d (CPUID_HV_BATCH_READ not handled?)\n",
                g_BatchContext->Status);
        }
        return STATUS_NOT_SUPPORTED;
    }

    {
        static volatile LONG s_cpuidDone = 0;
        LONG dCnt = InterlockedIncrement(&s_cpuidDone);
        if (dCnt <= 10 || (dCnt % 5000) == 0) {
            DbgPrint("[BatchRead] <<< VMEXIT DONE #%d: Status=%d SuccessCount=%u/%u\n",
                dCnt, g_BatchContext->Status, g_BatchContext->SuccessCount, count);
        }
    }

    /* 拷贝结果到调用者缓冲区 */
    __try {
        RtlCopyMemory(output, g_OutputBuffer, totalDataSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    *pSuccess = g_BatchContext->SuccessCount;
    return STATUS_SUCCESS;
}

/* ========================================================================
 *  单次 VMEXIT 读取 — 供 IOCTL_CE_READMEMORY 使用
 *
 *  将单次内存读取也走 VMEXIT 路径, 确保 First Scan / Memory Viewer
 *  等所有读取操作都不在 Guest R0 留下物理读取痕迹。
 *
 *  R3 已经将大块读取拆分为 ≤4096 字节的页对齐块,
 *  每次 IOCTL 调用此函数 = 1 次 CPUID VMEXIT。
 * ======================================================================== */
BOOLEAN HvBatchRead_SingleRead(ULONG64 pid, ULONG64 address, PVOID output, ULONG32 size)
{
    BATCH_READ_ENTRY entry;
    ULONG32 success = 0;
    NTSTATUS status;

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
 *  IOCTL 处理器 — CE DeviceIoControl 入口
 *
 *  输入布局 (SystemBuffer):
 *    [BATCH_READ_INPUT header] [BATCH_READ_ENTRY × Count]
 *
 *  输出布局 (SystemBuffer):
 *    [BATCH_READ_OUTPUT header] [Data × TotalSize]
 * ======================================================================== */

 /**
  * @brief 处理 IOCTL_CE_BATCH_READ
  *
  * 在 IOPLDispatcher.c 的 switch(IoControlCode) 中调用:
  *   case IOCTL_CE_BATCH_READ:
  *       ntStatus = HvBatchRead_Dispatch(
  *           Irp->AssociatedIrp.SystemBuffer,
  *           inputLength, outputLength, &info);
  *       break;
  */
NTSTATUS HvBatchRead_Dispatch(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG_PTR BytesReturned)
{
    NTSTATUS status;
    PBATCH_READ_INPUT inp;
    PBATCH_READ_ENTRY entries;
    ULONG32 count;
    ULONG32 headerSize;
    ULONG32 totalDataSize;
    ULONG32 successCount = 0;

    *BytesReturned = 0;

    if (!SystemBuffer)
        return STATUS_INVALID_PARAMETER;

    if (InputLength < sizeof(BATCH_READ_INPUT))
        return STATUS_BUFFER_TOO_SMALL;

    inp = (PBATCH_READ_INPUT)SystemBuffer;
    count = inp->Count;

    if (count == 0 || count > HV_BATCH_MAX_ENTRIES)
        return STATUS_INVALID_PARAMETER;

    /* 验证输入缓冲区包含所有 entries */
    headerSize = sizeof(BATCH_READ_INPUT);
    if (InputLength < headerSize + count * sizeof(BATCH_READ_ENTRY))
        return STATUS_BUFFER_TOO_SMALL;

    entries = (PBATCH_READ_ENTRY)((PUCHAR)SystemBuffer + headerSize);

    /* 计算总数据大小 */
    totalDataSize = 0;
    for (ULONG32 i = 0; i < count; i++) {
        if (entries[i].Size > PAGE_SIZE) return STATUS_INVALID_PARAMETER;
        totalDataSize += entries[i].Size;
    }

    /* 验证输出缓冲区足够大 */
    if (OutputLength < sizeof(BATCH_READ_OUTPUT) + totalDataSize)
        return STATUS_BUFFER_TOO_SMALL;

    /* 加锁 (一次只有一个批量操作, 共享预分配缓冲区) */
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