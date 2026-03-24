/**
 * @file SvmBridge.h
 * @brief CE 驱动 (DBKKernel) 与 SvmDebug 驱动的内核间通信桥接
 *
 * 将本文件和 SvmBridge.c 加入 CE 的 DBKKernel 工程。
 * DBKDrvr.c 最小改动:
 *   1. #include "SvmBridge.h"
 *   2. DriverEntry 末尾调用 SvmBridge_Init()
 *   3. UnloadDriver 中调用 SvmBridge_Cleanup()
 *   4. CE 打开目标进程时调用 SvmBridge_OnProcessOpen(pid)
 */

#ifndef SVMBRIDGE_H
#define SVMBRIDGE_H

#include <ntifs.h>
#include <windef.h>

 /* ================================================================
  * IOCTL codes (must match SvmDebug's DrvMain.cpp / DebugApi.h)
  * ================================================================ */
#define FILE_DEVICE_SVM  0x22

#define SVM_CTL(fn) \
    (ULONG)((FILE_DEVICE_SVM << 16) | ((fn) << 2))

  /* 保护类 IOCTL (0x820 系列) */
#define IOCTL_SVM_PROTECT_PID         SVM_CTL(0x820)
#define IOCTL_SVM_PROTECT_HWND        SVM_CTL(0x821)
#define IOCTL_SVM_CLEAR_ALL           SVM_CTL(0x823)
#define IOCTL_SVM_DISABLE_CALLBACKS   SVM_CTL(0x824)
#define IOCTL_SVM_RESTORE_CALLBACKS   SVM_CTL(0x825)

/* [NEW] 被调试进程标记 IOCTL (0x828-0x829, 与 DrvMain.cpp 对应) */
#define IOCTL_SVM_SET_DEBUGGED_PID    SVM_CTL(0x828)
#define IOCTL_SVM_UNSET_DEBUGGED_PID  SVM_CTL(0x829)
/* [COMPAT] */
#define IOCTL_SVM_ELEVATE_PID         IOCTL_SVM_SET_DEBUGGED_PID
#define IOCTL_SVM_UNELEVATE_PID       IOCTL_SVM_UNSET_DEBUGGED_PID

/* 调试类 IOCTL (0x830 系列) */
#define IOCTL_DBG_REGISTER_DEBUGGER   SVM_CTL(0x830)
#define IOCTL_DBG_ATTACH_PROCESS      SVM_CTL(0x831)
#define IOCTL_DBG_DETACH_PROCESS      SVM_CTL(0x832)
#define IOCTL_DBG_SET_HW_BP          SVM_CTL(0x833)
#define IOCTL_DBG_REMOVE_HW_BP       SVM_CTL(0x834)
#define IOCTL_DBG_SET_SW_BP          SVM_CTL(0x835)
#define IOCTL_DBG_REMOVE_SW_BP       SVM_CTL(0x836)
#define IOCTL_DBG_READ_SW_BP         SVM_CTL(0x837)

/* ================================================================
 * Communication structs (match SvmDebug DebugApi.h layout)
 * ================================================================ */
#pragma pack(push, 8)

typedef struct _SVM_PROTECT_INFO {
    ULONG64 Pid;
    WCHAR   ProcessName[260];
} SVM_PROTECT_INFO;

typedef struct _SVM_HW_BP_REQUEST {
    ULONG64 TargetPid;
    ULONG64 Address;
    ULONG   DrIndex;
    ULONG   Type;
    ULONG   Length;
    ULONG64 TargetCr3;
} SVM_HW_BP_REQUEST;

typedef struct _SVM_SW_BP_REQUEST {
    ULONG64 TargetPid;
    ULONG64 Address;
    UCHAR   OriginalByte;
    ULONG64 TargetCr3;
} SVM_SW_BP_REQUEST;

#pragma pack(pop)

/* ================================================================
 * CE custom IOCTL extension codes
 * CE (R3) 发送给 DBKKernel, DBKKernel 转发到 SvmDebug
 *
 * 添加到 DispatchIoctl 处理器中。
 * 输入缓冲区 = ULONG64 类型的目标 PID (大多数命令)
 * ================================================================ */
#define IOCTL_CE_SVM_INIT             SVM_CTL(0x900)  /* 无输入, 自动注册 CE */
#define IOCTL_CE_SVM_PROTECT_TARGET   SVM_CTL(0x901)  /* 输入: ULONG64 targetPid */
#define IOCTL_CE_SVM_DETACH_TARGET    SVM_CTL(0x902)  /* 输入: ULONG64 targetPid */
#define IOCTL_CE_SVM_SET_HW_BP       SVM_CTL(0x903)  /* 输入: SVM_HW_BP_REQUEST */
#define IOCTL_CE_SVM_REMOVE_HW_BP    SVM_CTL(0x904)  /* 输入: SVM_HW_BP_REQUEST */
#define IOCTL_CE_SVM_SET_SW_BP       SVM_CTL(0x905)  /* 输入/输出: SVM_SW_BP_REQUEST */
#define IOCTL_CE_SVM_REMOVE_SW_BP    SVM_CTL(0x906)  /* in: SVM_SW_BP_REQUEST */
#define IOCTL_CE_SVM_CLEANUP         SVM_CTL(0x907)  /* 无输入 */

 /* [NEW] 被调试进程状态设置 */
#define IOCTL_CE_SVM_SET_DEBUGGED    SVM_CTL(0x908)  /* 输入: ULONG64 targetPid */
#define IOCTL_CE_SVM_UNSET_DEBUGGED  SVM_CTL(0x909)  /* 输入: ULONG64 targetPid */
/* [COMPAT] */
#define IOCTL_CE_SVM_ELEVATE_PID     IOCTL_CE_SVM_SET_DEBUGGED
#define IOCTL_CE_SVM_UNELEVATE_PID   IOCTL_CE_SVM_UNSET_DEBUGGED

/* ================================================================
 * SvmDebug HvMemory IOCTL (直接转发, 不经 CE 自定义 IOCTL)
 * ================================================================ */
#define IOCTL_HV_QUERY_VM  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* HvQueryVirtualMemory 请求/响应结构体 (必须与 SvmDebug HvMemory.h 一致) */
#pragma pack(push, 1)
typedef struct _SVMBRIDGE_QVM_REQ {
    UINT64 TargetPid;
    UINT64 StartAddress;
} SVMBRIDGE_QVM_REQ;

typedef struct _SVMBRIDGE_QVM_RESP {
    UINT64 BaseAddress;
    UINT64 RegionSize;
    ULONG  Protection;
    ULONG  State;
    ULONG  Type;
} SVMBRIDGE_QVM_RESP;
#pragma pack(pop)

/* ================================================================
 * Public API
 * ================================================================ */

 /**
  * 初始化 SvmDebug 桥接。
  * 打开 \Device\SvmDebug, 注册 CE 为调试器, 保护 CE 进程。
  * 在 DriverEntry 中调用。即使 SvmDebug 未加载也安全。
  */
NTSTATUS SvmBridge_Init(void);

/**
 * 清理 — 关闭设备句柄。
 * 在 UnloadDriver 中调用。
 */
void SvmBridge_Cleanup(void);

/**
 * 检查 SvmDebug 桥接是否激活。
 */
BOOLEAN SvmBridge_IsActive(void);

/**
 * 将 CE 自身进程注册为受保护调试器。
 * 通常由 SvmBridge_Init 或首次 DispatchCreate 时自动调用。
 */
NTSTATUS SvmBridge_RegisterCE(HANDLE cePid);

/**
 * 保护并调试附加目标进程。
 * 在 CE 打开目标进程时调用。
 */
NTSTATUS SvmBridge_ProtectTarget(ULONG64 targetPid);

/**
 * 从目标分离调试。
 */
NTSTATUS SvmBridge_DetachTarget(ULONG64 targetPid);

/**
 * 硬件断点 (VMM 层 DR0-DR3)。
 */
NTSTATUS SvmBridge_SetHwBreakpoint(SVM_HW_BP_REQUEST* req);
NTSTATUS SvmBridge_RemoveHwBreakpoint(SVM_HW_BP_REQUEST* req);

/**
 * 软件断点 (物理内存 INT3 注入)。
 */
NTSTATUS SvmBridge_SetSwBreakpoint(SVM_SW_BP_REQUEST* req);
NTSTATUS SvmBridge_RemoveSwBreakpoint(SVM_SW_BP_REQUEST* req);

/**
 * 清除所有保护。
 */
NTSTATUS SvmBridge_ClearAll(void);

/**
 * [NEW] 标记目标进程为被调试状态。
 * CE attach 时调用, 将 PID 加入 SvmDebug 的 g_DebuggedPIDs。
 */
NTSTATUS SvmBridge_SetDebuggedPid(ULONG64 targetPid);

/**
 * [NEW] 取消目标进程的被调试状态。
 * CE detach 时调用。
 */
NTSTATUS SvmBridge_UnsetDebuggedPid(ULONG64 targetPid);

/* [COMPAT] */
#define SvmBridge_ElevatePid    SvmBridge_SetDebuggedPid
#define SvmBridge_UnelevatePid  SvmBridge_UnsetDebuggedPid

/**
 * [NEW] 通过 SvmDebug 调用真正的 ZwQueryVirtualMemory。
 * 调用来自 SvmDebug 上下文, ACE 看不到 CE 的 KeStackAttachProcess。
 * @return STATUS_SUCCESS 成功, 其他失败
 */
NTSTATUS SvmBridge_QueryVirtualMemory(
    UINT64   TargetPid,
    UINT64   StartAddress,
    PUINT64  OutBaseAddress,
    PUINT64  OutRegionSize,
    PULONG   OutProtection,
    PULONG   OutState,
    PULONG   OutType);

/**
 * 分发 CE 自定义 IOCTL (0x900 系列)。
 * 从 DispatchIoctl 的 default 分支调用。
 * 非桥接 IOCTL 返回 STATUS_INVALID_DEVICE_REQUEST。
 */
NTSTATUS SvmBridge_DispatchIoctl(
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputLength,
    PVOID OutputBuffer,
    ULONG OutputLength,
    PULONG_PTR Information);

#endif /* SVMBRIDGE_H */