/**
 * @file HvMemBridge.c
 * @brief CE 驱动内存读写的 Hypervisor 桥接实现
 *
 * 将 CE dbk64 驱动的内存读写替换为 SvmDebug Hypervisor 的 CPUID 超级调用。
 * 原始方式: KeAttachProcess + RtlCopyMemory (ACE 可检测)
 * 新方式:   CPUID hypercall → VMM 遍历页表 → 物理内存拷贝
 *
 * ACE 无法检测因为:
 *   - 无 KeAttachProcess (不切换到目标进程上下文)
 *   - 无 MmCopyVirtualMemory / NtRead/WriteVirtualMemory
 *   - 无 ObRegisterCallbacks 触发
 *   - VMM 运行在比 ACE 内核驱动更高的权限层
 */

#include "HvMemBridge.h"

/* Guest ↔ VMM 通信的共享上下文页 */
static PHV_RW_CONTEXT g_BridgeContext = NULL;
static ULONG64 g_BridgeContextPa = 0;
static BOOLEAN g_BridgeInitialized = FALSE;

/* 检查 SvmDebug Hypervisor 是否在运行 */
BOOLEAN HvBridge_IsHypervisorPresent(void)
{
    int regs[4] = { 0 };
    char vendorId[13] = { 0 };

    __cpuid(regs, 0x40000000);
    *(int*)(vendorId + 0) = regs[1];
    *(int*)(vendorId + 4) = regs[2];
    *(int*)(vendorId + 8) = regs[3];
    vendorId[12] = 0;

        /* 必须匹配 SvmDebug 的厂商字符串 */ "VtDebugView "
    return (strcmp(vendorId, "VtDebugView ") == 0);
}

/* 初始化共享上下文页 */
NTSTATUS HvBridge_Init(void)
{
    PHYSICAL_ADDRESS highAddr;
    highAddr.QuadPart = ~0ULL;

    if (g_BridgeInitialized) {
        return STATUS_SUCCESS;
    }

        /* 先检查 Hypervisor 是否存在 */
    if (!HvBridge_IsHypervisorPresent()) {
        DbgPrint("[HvBridge] SvmDebug hypervisor NOT detected!\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[HvBridge] SvmDebug hypervisor detected.\n");

        /* 分配共享上下文页 (连续物理内存) */
    g_BridgeContext = (PHV_RW_CONTEXT)MmAllocateContiguousMemory(
        PAGE_SIZE, highAddr);

    if (!g_BridgeContext) {
        DbgPrint("[HvBridge] Failed to allocate shared context\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_BridgeContext, PAGE_SIZE);
    g_BridgeContextPa = MmGetPhysicalAddress(g_BridgeContext).QuadPart;

    DbgPrint("[HvBridge] Shared context VA=%p PA=0x%llX\n",
        g_BridgeContext, g_BridgeContextPa);

    g_BridgeInitialized = TRUE;
    return STATUS_SUCCESS;
}

/* 清理释放 */
void HvBridge_Cleanup(void)
{
    if (g_BridgeContext) {
        MmFreeContiguousMemory(g_BridgeContext);
        g_BridgeContext = NULL;
        g_BridgeContextPa = 0;
    }
    g_BridgeInitialized = FALSE;
}

/**
 * @brief 获取进程的 CR3 (DirectoryTableBase)
 * @note KPROCESS 偏移 0x28, 适用于所有 Win10 x64 版本 (1507-22H2)
 */
static ULONG64 GetProcessDirBase(DWORD PID, PEPROCESS PEProcess)
{
    PEPROCESS proc = PEProcess;
    NTSTATUS status;

    if (proc == NULL) {
        status = PsLookupProcessByProcessId((PVOID)(UINT_PTR)PID, &proc);
        if (!NT_SUCCESS(status) || proc == NULL) {
            return 0;
        }
    }

        /* DirectoryTableBase 偏移, Win10 x64 所有版本均为 0x28 */
    ULONG64 cr3 = *(PULONG64)((PUCHAR)proc + 0x28);

    if (PEProcess == NULL) {
        ObDereferenceObject(proc);
    }

    return cr3;
}

/**
 * @brief 发起 CPUID 超级调用让 VMM 执行内存操作
 */
static BOOLEAN DoHypercallMemoryOp(
    ULONG64 TargetCr3,
    ULONG64 TargetVa,
    PVOID KernelBuffer,
    DWORD Size,
    BOOLEAN IsWrite)
{
    if (!g_BridgeInitialized || !g_BridgeContext) {
        return FALSE;
    }

    ULONG64 bufferPa = MmGetPhysicalAddress(KernelBuffer).QuadPart;
    if (bufferPa == 0) {
        return FALSE;
    }

        /* 填充共享上下文 */
    g_BridgeContext->TargetCr3 = TargetCr3;
    g_BridgeContext->SourceVa = TargetVa;
    g_BridgeContext->DestPa = bufferPa;
    g_BridgeContext->Size = Size;
    g_BridgeContext->IsWrite = IsWrite ? 1 : 0;
    g_BridgeContext->Status = 1; // Pending

        /* 内存屏障: 确保写入在超级调用前可见 */
    KeMemoryBarrier();

        /* 发起超级调用 */
    int regs[4] = { 0 };
    __cpuidex(regs, CPUID_HV_MEMORY_OP,
        IsWrite ? HV_MEM_OP_WRITE : HV_MEM_OP_READ);

    return (g_BridgeContext->Status == 0);
}

/**
 * @brief 读取进程内存 — CE ReadProcessMemory 的替代实现
 *
 * 原始实现: KeAttachProcess + RtlCopyMemory (ACE 可检测)
 * 新实现:   CPUID 超级调用 → VMM 物理内存拷贝 (ACE 不可见)
 *
 * @param PID        目标进程 PID
 * @param PEProcess  目标进程 EPROCESS (可为 NULL, 内部通过 PID 查找)
 * @param Address    目标进程中的虚拟地址
 * @param Size       读取字节数
 * @param Buffer     输出缓冲区
 * @return TRUE=成功, FALSE=失败
 */
BOOLEAN HvBridge_ReadProcessMemory(
    DWORD PID,
    PEPROCESS PEProcess,
    PVOID Address,
    DWORD Size,
    PVOID Buffer)
{
    if (Size == 0 || Buffer == NULL || Address == NULL) {
        return FALSE;
    }

        /* Hypervisor 不可用时返回 FALSE, 调用者应使用原始方法 */
    if (!g_BridgeInitialized) {
        return FALSE; // Caller should use original ReadProcessMemory
    }

    ULONG64 targetCr3 = GetProcessDirBase(PID, PEProcess);
    if (targetCr3 == 0) {
        return FALSE;
    }

        /* 分配非分页内核缓冲区 (VMM 映射需要有效物理地址) */
    PVOID kernelBuf = ExAllocatePoolWithTag(NonPagedPool, Size, 'HvBr');
    if (!kernelBuf) {
        return FALSE;
    }
    RtlZeroMemory(kernelBuf, Size);

        /* 按页边界分块处理 */
    DWORD bytesProcessed = 0;
    BOOLEAN success = TRUE;

    while (bytesProcessed < Size)
    {
        DWORD pageRemain = PAGE_SIZE - (DWORD)(((ULONG64)Address + bytesProcessed) & 0xFFF);
        DWORD chunkSize = Size - bytesProcessed;
        if (chunkSize > pageRemain) chunkSize = pageRemain;
        if (chunkSize > PAGE_SIZE) chunkSize = PAGE_SIZE;

        BOOLEAN ok = DoHypercallMemoryOp(
            targetCr3,
            (ULONG64)Address + bytesProcessed,
            (PUCHAR)kernelBuf + bytesProcessed,
            chunkSize,
            FALSE);

        if (!ok) {
            success = FALSE;
            break;
        }

        bytesProcessed += chunkSize;
    }

    if (success) {
                /* 从内核缓冲区拷贝到调用者缓冲区 */
        __try {
            RtlCopyMemory(Buffer, kernelBuf, Size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            success = FALSE;
        }
    }

    ExFreePoolWithTag(kernelBuf, 'HvBr');
    return success;
}

/**
 * @brief 写入进程内存 — CE WriteProcessMemory 的替代实现
 * @note 参数和返回值与 ReadProcessMemory 相同, 方向相反
 */
BOOLEAN HvBridge_WriteProcessMemory(
    DWORD PID,
    PEPROCESS PEProcess,
    PVOID Address,
    DWORD Size,
    PVOID Buffer)
{
    if (Size == 0 || Buffer == NULL || Address == NULL) {
        return FALSE;
    }

    if (!g_BridgeInitialized) {
        return FALSE;
    }

    ULONG64 targetCr3 = GetProcessDirBase(PID, PEProcess);
    if (targetCr3 == 0) {
        return FALSE;
    }

        /* 分配内核缓冲区并拷贝源数据 */
    PVOID kernelBuf = ExAllocatePoolWithTag(NonPagedPool, Size, 'HvBr');
    if (!kernelBuf) {
        return FALSE;
    }

    __try {
        RtlCopyMemory(kernelBuf, Buffer, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(kernelBuf, 'HvBr');
        return FALSE;
    }

        /* 按页边界分块处理 */
    DWORD bytesProcessed = 0;
    BOOLEAN success = TRUE;

    while (bytesProcessed < Size)
    {
        DWORD pageRemain = PAGE_SIZE - (DWORD)(((ULONG64)Address + bytesProcessed) & 0xFFF);
        DWORD chunkSize = Size - bytesProcessed;
        if (chunkSize > pageRemain) chunkSize = pageRemain;
        if (chunkSize > PAGE_SIZE) chunkSize = PAGE_SIZE;

        BOOLEAN ok = DoHypercallMemoryOp(
            targetCr3,
            (ULONG64)Address + bytesProcessed,
            (PUCHAR)kernelBuf + bytesProcessed,
            chunkSize,
            TRUE);

        if (!ok) {
            success = FALSE;
            break;
        }

        bytesProcessed += chunkSize;
    }

    ExFreePoolWithTag(kernelBuf, 'HvBr');
    return success;
}
