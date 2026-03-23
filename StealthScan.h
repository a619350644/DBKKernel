/**
 * @file StealthScan.h
 * @brief CE 隐身内存扫描引擎 — 修复错误内存 + 消除 ACE 检测
 *
 * === 修复的 BUG ===
 *
 * BUG 1 [根因: 读到错误内存]:
 *   SvmReadPte() 使用 MmGetVirtualForPhysical() 读取目标进程的页表条目。
 *   该函数从 PFN 数据库中查找物理页对应的虚拟地址, 返回的 VA 位于
 *   页表自映射区域 (Page Table Self-Map)。
 *   自映射区域是 CR3 相关的: 同一个 VA 在不同进程上下文中指向不同的物理页。
 *   CE 驱动执行时 (CE 的 CR3 加载), 自映射 VA 指向 CE 自己的页表,
 *   而非目标进程的页表!
 *   结果: 页表遍历读到 CE 自己的 PTE → 翻译出错误 PA → 读到错误内存。
 *   修复: MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) 直接从物理地址读取。
 *
 * BUG 2 [CR3 高位污染]:
 *   cr3_raw & ~0xFFFULL 不清除 bit63 (NOFLUSH)。
 *   修复: & 0x000FFFFFFFFFF000ULL 只保留 bit12-51。
 *
 * BUG 3 [KVAS 未处理]:
 *   假设 AMD 不启 KVAS, 只读 +0x28。Win10 1903+ 某些 AMD 也启用。
 *   修复: +0x28 翻译失败时回退 +0x280 (UserDirectoryTableBase)。
 *
 * BUG 4 [CR3 缓存无失效]:
 *   修复: 8 条目 LRU + 翻译失败时自动失效重新查询。
 *
 * @author yewilliam
 * @date 2026/03/23
 */

#ifndef STEALTH_SCAN_H
#define STEALTH_SCAN_H

#include <ntifs.h>
#include <windef.h>

 /* MmCopyMemory 声明 */
#ifndef MM_COPY_MEMORY_PHYSICAL
#define MM_COPY_MEMORY_PHYSICAL 0x1
#endif

#ifndef _STEALTH_MM_COPY_ADDRESS_DEFINED
#define _STEALTH_MM_COPY_ADDRESS_DEFINED
typedef union _STEALTH_MM_COPY_ADDRESS {
    PVOID            VirtualAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
} STEALTH_MM_COPY_ADDRESS;
#endif

NTSYSAPI NTSTATUS NTAPI MmCopyMemory(
    PVOID TargetAddress, STEALTH_MM_COPY_ADDRESS SourceAddress,
    SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred);

/** CR3 物理地址掩码: bit12-51, 清除 PCID(bit0-11) 和 NOFLUSH(bit63) */
#define CR3_PA_MASK  0x000FFFFFFFFFF000ULL

/** EPROCESS 偏移 */
#define EPROCESS_DTB       0x28   /* DirectoryTableBase */
#define EPROCESS_USER_DTB  0x280  /* UserDirectoryTableBase */

#define STEALTH_PT_ENTRIES  512

/* 页表页缓存 */
typedef struct _STEALTH_LEVEL_CACHE {
    UINT64  BasePa;
    UINT64  Entries[STEALTH_PT_ENTRIES];
    BOOLEAN Valid;
} STEALTH_LEVEL_CACHE;

typedef struct _STEALTH_PT_CACHE {
    STEALTH_LEVEL_CACHE Pml4;
    STEALTH_LEVEL_CACHE Pdpt;
    STEALTH_LEVEL_CACHE Pd;
    STEALTH_LEVEL_CACHE Pt;
    UINT64              Cr3;
} STEALTH_PT_CACHE;

extern STEALTH_PT_CACHE g_StealthCache;

/* CR3 缓存 */
#define STEALTH_CR3_CACHE_SIZE  8

typedef struct _STEALTH_CR3_ENTRY {
    UINT64 Pid;
    UINT64 Cr3;         /* DirectoryTableBase */
    UINT64 UserCr3;     /* UserDirectoryTableBase (KVAS fallback) */
    UINT64 LastUseTick;
} STEALTH_CR3_ENTRY;

extern STEALTH_CR3_ENTRY g_Cr3Cache[STEALTH_CR3_CACHE_SIZE];

/* Public API */
VOID    StealthInit(VOID);
VOID    StealthCleanup(VOID);
VOID    StealthResetPtCache(VOID);
UINT64  StealthGetCr3(UINT64 Pid);
VOID    StealthInvalidateCr3(UINT64 Pid);
UINT64  StealthTranslateVa(UINT64 Cr3, UINT64 Va);
BOOLEAN StealthDirectRead(UINT64 Pid, UINT64 Addr, PVOID OutBuf, ULONG Size);
BOOLEAN StealthDirectWrite(UINT64 Pid, UINT64 Addr, PVOID Data, ULONG Size);
DWORD   StealthGetPageProtect(UINT64 Cr3, UINT64 Va, PUINT64 pSkipSize);
BOOLEAN StealthQueryRegion(UINT64 Cr3, UINT64 StartVa, PUINT_PTR OutSize, PDWORD OutProtect);
UINT64  StealthGetPhysAddr(UINT64 Pid, UINT64 Va);
UINT64  StealthGetProcessCr3(UINT64 Pid);

#endif