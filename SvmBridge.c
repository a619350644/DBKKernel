/**
 * @file SvmBridge.c
 * @brief CE 驱动 (DBKKernel) 与 SvmDebug 驱动的内核间通信桥接
 *
 * 通过 ZwCreateFile + ZwDeviceIoControlFile 与 SvmDebug 驱动通信。
 * 所有通信在 PASSIVE_LEVEL 内核模式下进行。
 */

#pragma warning(disable: 4100 4101 4189)

#include "SvmBridge.h"
#include <ntstrsafe.h>

 /* ================================================================
  * Internal state
  * ================================================================ */
static HANDLE  g_SvmDeviceHandle = NULL;
static BOOLEAN g_SvmActive = FALSE;
static HANDLE  g_RegisteredCePid = NULL;

/* ================================================================
 * Internal: Open SvmDebug device
 * ================================================================ */
static NTSTATUS SvmBridge_OpenDevice(void)
{
    NTSTATUS status;
    UNICODE_STRING devName;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;

    if (g_SvmDeviceHandle)
        return STATUS_SUCCESS;

    RtlInitUnicodeString(&devName, L"\\Device\\SvmDebug");
    InitializeObjectAttributes(&oa, &devName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(
        &g_SvmDeviceHandle,
        GENERIC_READ | GENERIC_WRITE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        0,
        NULL, 0);

    if (!NT_SUCCESS(status)) {
        g_SvmDeviceHandle = NULL;
        DbgPrint("[SvmBridge] Cannot open \\Device\\SvmDebug: 0x%X\n", status);
    }

    return status;
}

/* ================================================================
 * Internal: Send IOCTL to SvmDebug
 * ================================================================ */
static NTSTATUS SvmBridge_SendIoctl(
    ULONG IoCtl,
    PVOID InBuf, ULONG InLen,
    PVOID OutBuf, ULONG OutLen)
{
    IO_STATUS_BLOCK iosb = { 0 };
    NTSTATUS status;

    if (!g_SvmDeviceHandle) {
        status = SvmBridge_OpenDevice();
        if (!NT_SUCCESS(status))
            return status;
    }

    status = ZwDeviceIoControlFile(
        g_SvmDeviceHandle,
        NULL,       /* Event */
        NULL,       /* ApcRoutine */
        NULL,       /* ApcContext */
        &iosb,
        IoCtl,
        InBuf, InLen,
        OutBuf, OutLen);

    return status;
}

/* ================================================================
 * Public: Init
 * ================================================================ */
NTSTATUS SvmBridge_Init(void)
{
    NTSTATUS status;

    DbgPrint("[SvmBridge] Initializing...\n");

    status = SvmBridge_OpenDevice();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SvmBridge] SvmDebug not available (0x%X). Bridge disabled.\n", status);
        g_SvmActive = FALSE;
        return status;  /* 非致命: CE 可在无 SvmDebug 时独立运行 */
    }

    g_SvmActive = TRUE;
    DbgPrint("[SvmBridge] Connected to SvmDebug.\n");

    return STATUS_SUCCESS;
}

/* ================================================================
 * Public: Cleanup
 * ================================================================ */
void SvmBridge_Cleanup(void)
{
    if (g_SvmDeviceHandle) {
        /* 关闭前清除所有保护 */
        SvmBridge_ClearAll();

        ZwClose(g_SvmDeviceHandle);
        g_SvmDeviceHandle = NULL;
    }
    g_SvmActive = FALSE;
    g_RegisteredCePid = NULL;

    DbgPrint("[SvmBridge] Cleaned up.\n");
}

/* ================================================================
 * Public: IsActive
 * ================================================================ */
BOOLEAN SvmBridge_IsActive(void)
{
    return g_SvmActive;
}

/* ================================================================
 * Public: Register CE as debugger + protect CE process
 * ================================================================ */
NTSTATUS SvmBridge_RegisterCE(HANDLE cePid)
{
    NTSTATUS status;
    ULONG64 pid64;
    SVM_PROTECT_INFO protInfo = { 0 };

    if (!g_SvmActive)
        return STATUS_DEVICE_NOT_READY;

    if (g_RegisteredCePid == cePid)
        return STATUS_SUCCESS;  /* 已注册, 跳过 */

    pid64 = (ULONG64)(ULONG_PTR)cePid;

    /* 1. 注册为调试器 */
    status = SvmBridge_SendIoctl(
        IOCTL_DBG_REGISTER_DEBUGGER,
        &pid64, sizeof(pid64),
        NULL, 0);

    if (NT_SUCCESS(status)) {
        DbgPrint("[SvmBridge] CE PID %llu registered as debugger\n", pid64);
    }
    else {
        DbgPrint("[SvmBridge] Register debugger failed: 0x%X\n", status);
        return status;
    }

    /* 2. 保护 CE 进程 (从枚举中隐藏) */
    protInfo.Pid = pid64;
    status = SvmBridge_SendIoctl(
        IOCTL_SVM_PROTECT_PID,
        &protInfo, sizeof(protInfo),
        NULL, 0);

    if (NT_SUCCESS(status)) {
        DbgPrint("[SvmBridge] CE PID %llu protected\n", pid64);
        g_RegisteredCePid = cePid;
    }

    return status;
}

/* ================================================================
 * Public: Protect + attach target
 * ================================================================ */
NTSTATUS SvmBridge_ProtectTarget(ULONG64 targetPid)
{
    NTSTATUS status;
    SVM_PROTECT_INFO protInfo = { 0 };
    ULONG64 pid64 = targetPid;

    if (!g_SvmActive)
        return STATUS_DEVICE_NOT_READY;

    /* 保护目标进程 */
    protInfo.Pid = targetPid;
    status = SvmBridge_SendIoctl(
        IOCTL_SVM_PROTECT_PID,
        &protInfo, sizeof(protInfo),
        NULL, 0);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[SvmBridge] Protect PID %llu failed: 0x%X\n", targetPid, status);
        return status;
    }

    /* [NEW] 标记目标为被调试状态
     * 各 Hook 函数据此判断: CE 操作该进程 → 完全透传 */
    SvmBridge_SetDebuggedPid(targetPid);

    /* 附加调试 (影子调试端口) */
    status = SvmBridge_SendIoctl(
        IOCTL_DBG_ATTACH_PROCESS,
        &pid64, sizeof(pid64),
        NULL, 0);

    if (NT_SUCCESS(status)) {
        DbgPrint("[SvmBridge] Target PID %llu: protected + elevated + debug attached\n", targetPid);
    }
    else {
        DbgPrint("[SvmBridge] Attach PID %llu failed: 0x%X\n", targetPid, status);
    }

    return status;
}

/* ================================================================
 * Public: Detach
 * ================================================================ */
NTSTATUS SvmBridge_DetachTarget(ULONG64 targetPid)
{
    ULONG64 pid64 = targetPid;
    NTSTATUS status;

    if (!g_SvmActive)
        return STATUS_DEVICE_NOT_READY;

    /* [NEW] 先清除被调试状态 */
    SvmBridge_UnsetDebuggedPid(targetPid);

    status = SvmBridge_SendIoctl(
        IOCTL_DBG_DETACH_PROCESS,
        &pid64, sizeof(pid64),
        NULL, 0);

    DbgPrint("[SvmBridge] Target PID %llu: detached + undebugged, status=0x%X\n",
        targetPid, status);

    return status;
}

/* ================================================================
 * Public: Breakpoints
 * ================================================================ */
NTSTATUS SvmBridge_SetHwBreakpoint(SVM_HW_BP_REQUEST* req)
{
    if (!g_SvmActive) return STATUS_DEVICE_NOT_READY;
    return SvmBridge_SendIoctl(IOCTL_DBG_SET_HW_BP, req, sizeof(*req), NULL, 0);
}

NTSTATUS SvmBridge_RemoveHwBreakpoint(SVM_HW_BP_REQUEST* req)
{
    if (!g_SvmActive) return STATUS_DEVICE_NOT_READY;
    return SvmBridge_SendIoctl(IOCTL_DBG_REMOVE_HW_BP, req, sizeof(*req), NULL, 0);
}

NTSTATUS SvmBridge_SetSwBreakpoint(SVM_SW_BP_REQUEST* req)
{
    if (!g_SvmActive) return STATUS_DEVICE_NOT_READY;
    return SvmBridge_SendIoctl(IOCTL_DBG_SET_SW_BP,
        req, sizeof(*req), req, sizeof(*req));
}

NTSTATUS SvmBridge_RemoveSwBreakpoint(SVM_SW_BP_REQUEST* req)
{
    if (!g_SvmActive) return STATUS_DEVICE_NOT_READY;
    return SvmBridge_SendIoctl(IOCTL_DBG_REMOVE_SW_BP, req, sizeof(*req), NULL, 0);
}

/* ================================================================
 * Public: Clear all
 * ================================================================ */
NTSTATUS SvmBridge_ClearAll(void)
{
    if (!g_SvmActive) return STATUS_DEVICE_NOT_READY;
    return SvmBridge_SendIoctl(IOCTL_SVM_CLEAR_ALL, NULL, 0, NULL, 0);
}

/* ================================================================
 * [NEW] 被调试进程标记 — 语义从"升权"改为"被调试"
 *
 * IOCTL 码保持 0x828/0x829 不变, 只是语义更准确。
 * ================================================================ */
NTSTATUS SvmBridge_SetDebuggedPid(ULONG64 targetPid)
{
    SVM_PROTECT_INFO info = { 0 };

    if (!g_SvmActive)
        return STATUS_DEVICE_NOT_READY;

    info.Pid = targetPid;

    NTSTATUS status = SvmBridge_SendIoctl(
        IOCTL_SVM_SET_DEBUGGED_PID,
        &info, sizeof(info),
        NULL, 0);

    if (NT_SUCCESS(status)) {
        DbgPrint("[SvmBridge] PID %llu marked as debugged\n", targetPid);
    }
    else {
        DbgPrint("[SvmBridge] Set debugged PID %llu failed: 0x%X\n", targetPid, status);
    }

    return status;
}

NTSTATUS SvmBridge_UnsetDebuggedPid(ULONG64 targetPid)
{
    SVM_PROTECT_INFO info = { 0 };

    if (!g_SvmActive)
        return STATUS_DEVICE_NOT_READY;

    info.Pid = targetPid;

    NTSTATUS status = SvmBridge_SendIoctl(
        IOCTL_SVM_UNSET_DEBUGGED_PID,
        &info, sizeof(info),
        NULL, 0);

    if (NT_SUCCESS(status)) {
        DbgPrint("[SvmBridge] PID %llu unmarked as debugged\n", targetPid);
    }
    else {
        DbgPrint("[SvmBridge] Unset debugged PID %llu failed: 0x%X\n", targetPid, status);
    }

    return status;
}

/* ================================================================
 * [NEW] 通过 SvmDebug 调用真正的 ZwQueryVirtualMemory
 *
 * CE -> dbk64 -> SvmBridge -> SvmDebug (IOCTL_HV_QUERY_VM)
 *   -> ZwQueryVirtualMemory(KernelMode, OBJ_KERNEL_HANDLE)
 *
 * ACE 视角: KeStackAttachProcess 的调用栈来自 SvmDebug, 不是 CE 驱动
 * ================================================================ */
NTSTATUS SvmBridge_QueryVirtualMemory(
    UINT64   TargetPid,
    UINT64   StartAddress,
    PUINT64  OutBaseAddress,
    PUINT64  OutRegionSize,
    PULONG   OutProtection,
    PULONG   OutState,
    PULONG   OutType)
{
    SVMBRIDGE_QVM_REQ req = { 0 };
    SVMBRIDGE_QVM_RESP resp = { 0 };
    NTSTATUS status;

    if (!g_SvmActive)
        return STATUS_DEVICE_NOT_READY;

    req.TargetPid = TargetPid;
    req.StartAddress = StartAddress;

    status = SvmBridge_SendIoctl(
        IOCTL_HV_QUERY_VM,
        &req, sizeof(req),
        &resp, sizeof(resp));

    if (NT_SUCCESS(status)) {
        if (OutBaseAddress) *OutBaseAddress = resp.BaseAddress;
        if (OutRegionSize)  *OutRegionSize = resp.RegionSize;
        if (OutProtection)  *OutProtection = resp.Protection;
        if (OutState)       *OutState = resp.State;
        if (OutType)        *OutType = resp.Type;
    }

    return status;
}

/* ================================================================
 * 公开接口: 分发 CE 自定义 IOCTL (0x900 系列)
 *
 * 如果不是桥接 IOCTL, 返回 STATUS_INVALID_DEVICE_REQUEST,
 * 让调用者继续处理其他 IOCTL。
 * ================================================================ */
NTSTATUS SvmBridge_DispatchIoctl(
    ULONG   IoControlCode,
    PVOID   InputBuffer,
    ULONG   InputLength,
    PVOID   OutputBuffer,
    ULONG   OutputLength,
    PULONG_PTR Information)
{
    NTSTATUS status = STATUS_SUCCESS;
    *Information = 0;

    switch (IoControlCode)
    {
    case IOCTL_CE_SVM_INIT:
    {
        /* 注册调用进程为调试器并保护 */
        HANDLE callerPid = PsGetCurrentProcessId();
        status = SvmBridge_RegisterCE(callerPid);
        break;
    }

    case IOCTL_CE_SVM_PROTECT_TARGET:
    {
        if (InputLength < sizeof(ULONG64) || !InputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        ULONG64 targetPid = *(ULONG64*)InputBuffer;
        status = SvmBridge_ProtectTarget(targetPid);
        break;
    }

    case IOCTL_CE_SVM_DETACH_TARGET:
    {
        if (InputLength < sizeof(ULONG64) || !InputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        ULONG64 targetPid = *(ULONG64*)InputBuffer;
        status = SvmBridge_DetachTarget(targetPid);
        break;
    }

    case IOCTL_CE_SVM_SET_HW_BP:
    {
        if (InputLength < sizeof(SVM_HW_BP_REQUEST) || !InputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = SvmBridge_SetHwBreakpoint((SVM_HW_BP_REQUEST*)InputBuffer);
        break;
    }

    case IOCTL_CE_SVM_REMOVE_HW_BP:
    {
        if (InputLength < sizeof(SVM_HW_BP_REQUEST) || !InputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = SvmBridge_RemoveHwBreakpoint((SVM_HW_BP_REQUEST*)InputBuffer);
        break;
    }

    case IOCTL_CE_SVM_SET_SW_BP:
    {
        if (InputLength < sizeof(SVM_SW_BP_REQUEST) || !InputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        SVM_SW_BP_REQUEST req = *(SVM_SW_BP_REQUEST*)InputBuffer;
        status = SvmBridge_SetSwBreakpoint(&req);
        if (NT_SUCCESS(status) && OutputBuffer && OutputLength >= sizeof(SVM_SW_BP_REQUEST)) {
            *(SVM_SW_BP_REQUEST*)OutputBuffer = req;
            *Information = sizeof(SVM_SW_BP_REQUEST);
        }
        break;
    }

    case IOCTL_CE_SVM_REMOVE_SW_BP:
    {
        if (InputLength < sizeof(SVM_SW_BP_REQUEST) || !InputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = SvmBridge_RemoveSwBreakpoint((SVM_SW_BP_REQUEST*)InputBuffer);
        break;
    }

    case IOCTL_CE_SVM_CLEANUP:
    {
        status = SvmBridge_ClearAll();
        break;
    }

    /* ================================================================
     * [NEW] Handle elevation IOCTLs
     * CE R3 -> DBKKernel -> SvmBridge -> SvmDebug -> AddElevatedPid()
     * ================================================================ */
    case IOCTL_CE_SVM_SET_DEBUGGED:   /* 0x908, 兼容旧 IOCTL_CE_SVM_ELEVATE_PID */
    {
        if (InputLength < sizeof(ULONG64) || !InputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        ULONG64 targetPid = *(ULONG64*)InputBuffer;
        status = SvmBridge_SetDebuggedPid(targetPid);
        break;
    }

    case IOCTL_CE_SVM_UNSET_DEBUGGED:  /* 0x909, 兼容旧 IOCTL_CE_SVM_UNELEVATE_PID */
    {
        if (InputLength < sizeof(ULONG64) || !InputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        ULONG64 targetPid = *(ULONG64*)InputBuffer;
        status = SvmBridge_UnsetDebuggedPid(targetPid);
        break;
    }

    default:
        return STATUS_INVALID_DEVICE_REQUEST; /* 不是我们的 IOCTL, 交由调用者处理 */
    }

    return status;
}