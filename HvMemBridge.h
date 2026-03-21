/**
 * @file HvMemBridge.h
 * @brief CE dbk64 内存读写的 Hypervisor 替代接口
 *
 * 将 KeAttachProcess + RtlCopyMemory 替换为 CPUID 超级调用
 *
 * 集成方法:
 *   1. 将本文件和 HvMemBridge.c 加入 CE dbk64 驱动工程
 *   2. 在 memscan.c 中将 ReadProcessMemory/WriteProcessMemory 的实现
 *      替换为 HvBridge_ReadProcessMemory / HvBridge_WriteProcessMemory
 *   3. 或使用文件底部的 #define 宏在编译时重定向
 */

#ifndef HV_MEM_BRIDGE_H
#define HV_MEM_BRIDGE_H

#include <ntifs.h>

/* 必须与 SvmDebug 的 Common.h 一致 */
#define CPUID_HV_MEMORY_OP    0x41414150
#define HV_MEM_OP_READ        0x01
#define HV_MEM_OP_WRITE       0x02

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

/* CE 内存读写函数的替代实现
 * 与 memscan.c 中原始 ReadProcessMemory/WriteProcessMemory 签名一致 */
BOOLEAN HvBridge_ReadProcessMemory(DWORD PID, PEPROCESS PEProcess, PVOID Address, DWORD Size, PVOID Buffer);
BOOLEAN HvBridge_WriteProcessMemory(DWORD PID, PEPROCESS PEProcess, PVOID Address, DWORD Size, PVOID Buffer);

/* 编译时重定向: 取消注释以自动替换 CE 的原始函数 */
// #define ReadProcessMemory  HvBridge_ReadProcessMemory
// #define WriteProcessMemory HvBridge_WriteProcessMemory

#endif // HV_MEM_BRIDGE_H
