/**
 * @file HvMemBridge.h
 * @brief CE dbk64 内存读写的 Hypervisor 替代接口
 *
 * 将 KeAttachProcess + RtlCopyMemory 替换为 CPUID 超级调用
 */

#ifndef HV_MEM_BRIDGE_H
#define HV_MEM_BRIDGE_H

#include <ntifs.h>
#include <windef.h>


 /* 必须与 SvmDebug 的 Common.h 一致 */
#define CPUID_HV_MEMORY_OP    0x41414150
#define HV_MEM_OP_READ        0x01
#define HV_MEM_OP_WRITE       0x02
#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
/* 共享上下文结构体 — 必须与 SvmDebug 的 HvMemory.h 完全一致 */
typedef struct _HV_RW_CONTEXT {
    ULONG64 TargetCr3;
    ULONG64 SourceVa;
    ULONG64 DestPa;
    ULONG64 Size;
    ULONG64 IsWrite;
    volatile LONG Status;
} HV_RW_CONTEXT, * PHV_RW_CONTEXT;

/* 初始化桥接 (驱动启动时调用一次) */
NTSTATUS HvBridge_Init(void);

/* 清理 (驱动卸载时调用) */
void HvBridge_Cleanup(void);

/* 检查 SvmDebug Hypervisor 是否存在 */
BOOLEAN HvBridge_IsHypervisorPresent(void);

/* CE 内存读写函数的替代实现 */
BOOLEAN HvBridge_ReadProcessMemory(DWORD PID, PEPROCESS PEProcess, PVOID Address, DWORD Size, PVOID Buffer);
BOOLEAN HvBridge_WriteProcessMemory(DWORD PID, PEPROCESS PEProcess, PVOID Address, DWORD Size, PVOID Buffer);

/* VirtualQuery 替代: 通过内核句柄查询, 不使用 KeAttachProcess */
BOOLEAN HvBridge_QueryVirtualMemory(
    DWORD PID, PEPROCESS PEProcess,
    PVOID Address, PVOID MemoryInfo, SIZE_T InfoLength,
    PUINT_PTR pRegionLength, PUINT_PTR pBaseAddress);

#endif /* HV_MEM_BRIDGE_H */