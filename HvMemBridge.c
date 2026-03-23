/**
 * @file HvMemBridge.c
 * @brief CE 驱动内存读写的 Hypervisor 桥接实现
 *
 * 将 CE dbk64 驱动的内存读写替换为 SvmDebug Hypervisor 的 CPUID 超级调用。
 * 原始方式: KeAttachProcess + RtlCopyMemory (反作弊可检测)
 * 新方式:   CPUID hypercall → VMM 遍历页表 → 物理内存拷贝
 */

#include "HvMemBridge.h"
#include <intrin.h>

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

    /* 必须匹配 SvmDebug 的厂商字符串 */
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

    /* VMM 限制: HvHandleMemoryOp 拒绝 > 1MB 的请求 */
    if (Size == 0 || Size > 0x100000) {
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
    g_BridgeContext->Status = 1; /* Pending */

    /* 内存屏障: 确保写入在超级调用前可见 */
    KeMemoryBarrier();

    /* 发起超级调用 */
    {
        int regs[4] = { 0 };
        __cpuidex(regs, CPUID_HV_MEMORY_OP,
            IsWrite ? HV_MEM_OP_WRITE : HV_MEM_OP_READ);
    }

    return (g_BridgeContext->Status == 0);
}

/**
 * @brief 读取进程内存 — CE ReadProcessMemory 的替代实现
 *
 * [v18] 一次 CPUID 超级调用处理整个请求, VMM 内部逐页循环
 * 旧方案: N 页 = N 次 CPUID VMEXIT
 * 新方案: N 页 = 1 次 CPUID VMEXIT (VMM HvHandleMemoryOp 内部循环)
 *
 * 关键: 使用 MmAllocateContiguousMemory 保证物理连续
 * VMM 侧 PhysicalMemoryCopy_Vmm 用 bpa+offset 寻址, 要求缓冲区物理连续
 */
BOOLEAN HvBridge_ReadProcessMemory(
    DWORD PID,
    PEPROCESS PEProcess,
    PVOID Address,
    DWORD Size,
    PVOID Buffer)
{
    ULONG64 targetCr3;
    PVOID kernelBuf;
    BOOLEAN success;
    PHYSICAL_ADDRESS highAddr;

    if (Size == 0 || Buffer == NULL || Address == NULL) {
        return FALSE;
    }

    if (!g_BridgeInitialized) {
        return FALSE;
    }

    targetCr3 = GetProcessDirBase(PID, PEProcess);
    if (targetCr3 == 0) {
        return FALSE;
    }

    /* 物理连续缓冲区 — VMM 用 PA+offset 寻址, 必须连续 */
    highAddr.QuadPart = ~0ULL;
    kernelBuf = MmAllocateContiguousMemory(Size, highAddr);
    if (!kernelBuf) {
        return FALSE;
    }
    RtlZeroMemory(kernelBuf, Size);

    /* 一次超级调用处理整个请求 — VMM 内部逐页翻译+拷贝 */
    success = DoHypercallMemoryOp(targetCr3, (ULONG64)Address, kernelBuf, Size, FALSE);

    if (success) {
        __try {
            RtlCopyMemory(Buffer, kernelBuf, Size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            success = FALSE;
        }
    }

    MmFreeContiguousMemory(kernelBuf);
    return success;
}

/**
 * @brief 写入进程内存 — CE WriteProcessMemory 的替代实现
 *
 * [v18] 一次 CPUID 超级调用处理整个写入请求
 */
BOOLEAN HvBridge_WriteProcessMemory(
    DWORD PID,
    PEPROCESS PEProcess,
    PVOID Address,
    DWORD Size,
    PVOID Buffer)
{
    ULONG64 targetCr3;
    PVOID kernelBuf;
    BOOLEAN success;
    PHYSICAL_ADDRESS highAddr;

    if (Size == 0 || Buffer == NULL || Address == NULL) {
        return FALSE;
    }

    if (!g_BridgeInitialized) {
        return FALSE;
    }

    targetCr3 = GetProcessDirBase(PID, PEProcess);
    if (targetCr3 == 0) {
        return FALSE;
    }

    /* 物理连续缓冲区 — VMM 用 PA+offset 寻址, 必须连续 */
    highAddr.QuadPart = ~0ULL;
    kernelBuf = MmAllocateContiguousMemory(Size, highAddr);
    if (!kernelBuf) {
        return FALSE;
    }

    __try {
        RtlCopyMemory(kernelBuf, Buffer, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MmFreeContiguousMemory(kernelBuf);
        return FALSE;
    }

    /* 一次超级调用处理整个写入请求 — VMM 内部逐页翻译+拷贝 */
    success = DoHypercallMemoryOp(targetCr3, (ULONG64)Address, kernelBuf, Size, TRUE);

    MmFreeContiguousMemory(kernelBuf);
    return success;
}

/**
 * @brief 通过内核句柄查询虚拟内存区域 — 替代 KeAttachProcess + ZwQueryVirtualMemory
 */
BOOLEAN HvBridge_QueryVirtualMemory(
    DWORD PID,
    PEPROCESS PEProcess,
    PVOID Address,
    PVOID MemoryInfo,
    SIZE_T InfoLength,
    PUINT_PTR pRegionLength,
    PUINT_PTR pBaseAddress)
{
    PEPROCESS proc = PEProcess;
    NTSTATUS status;
    BOOLEAN needDeref = FALSE;
    HANDLE kernelHandle = NULL;
    SIZE_T returnLength = 0;

    /* MEMORY_BASIC_INFORMATION 内部定义, 避免与用户态头文件冲突 */
    struct {
        PVOID  BaseAddress;
        PVOID  AllocationBase;
        ULONG  AllocationProtect;
        USHORT PartitionId;
        USHORT Padding;
        SIZE_T RegionSize;
        ULONG  State;
        ULONG  Protect;
        ULONG  Type;
    } mbi;

    UNREFERENCED_PARAMETER(MemoryInfo);
    UNREFERENCED_PARAMETER(InfoLength);

    if (!pRegionLength || !pBaseAddress)
        return FALSE;

    *pRegionLength = 0;
    *pBaseAddress = 0;

    /* 获取 EPROCESS */
    if (proc == NULL) {
        status = PsLookupProcessByProcessId((PVOID)(UINT_PTR)PID, &proc);
        if (!NT_SUCCESS(status) || proc == NULL)
            return FALSE;
        needDeref = TRUE;
    }

    /* 创建内核句柄 — 不触发 ObRegisterCallbacks */
    status = ObOpenObjectByPointer(
        proc,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &kernelHandle);

    if (needDeref)
        ObDereferenceObject(proc);

    if (!NT_SUCCESS(status) || !kernelHandle)
        return FALSE;

    /* 使用内核句柄查询 — 不需要 KeAttachProcess */
    RtlZeroMemory(&mbi, sizeof(mbi));

    status = ZwQueryVirtualMemory(
        kernelHandle,
        Address,
        0,  /* MemoryBasicInformation */
        &mbi,
        sizeof(mbi),
        &returnLength);

    ZwClose(kernelHandle);

    if (!NT_SUCCESS(status))
        return FALSE;

    *pBaseAddress = (UINT_PTR)mbi.BaseAddress;
    *pRegionLength = (UINT_PTR)mbi.RegionSize;

    return TRUE;
}