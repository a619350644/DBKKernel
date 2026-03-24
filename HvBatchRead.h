/**
 * @file HvBatchRead.h
 * @brief 批量散射读取 (Scatter-Gather Batch Read) — Guest/Host 共享定义
 *
 * ═══════════════════════════════════════════════════════════════════════
 *  将此文件同时放入 SvmDebug/SvmDebug/ 和 DBKKernel/ 两个项目中。
 *
 *  设计:
 *    CE 扫描内存时将多个读取请求打包为散射表,
 *    通过一次 CPUID VMEXIT 传给 VMM Host,
 *    Host 在物理层一次性读取所有条目返回结果。
 *
 *  数据流:
 *    CE(R3) ─IOCTL→ DBKKernel(R0) 构建散射表+输出缓冲区
 *      → CPUID(CPUID_HV_BATCH_READ) → VMEXIT
 *      → VMM Host: 遍历散射表, 逐条页表遍历+物理直读
 *      → VMRUN 返回 Guest → DBKKernel 拷贝结果给 CE
 * ═══════════════════════════════════════════════════════════════════════
 */

#ifndef HV_BATCH_READ_H
#define HV_BATCH_READ_H

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CPUID 超级调用叶号 (紧接 CPUID_HV_MEMORY_OP = 0x41414150) */
#define CPUID_HV_BATCH_READ     0x41414151

/* 限制 */
#define HV_BATCH_MAX_ENTRIES    512
#define HV_BATCH_MAX_OUTPUT     (4 * 1024 * 1024)  /* 4MB */

/* ========================================================================
 *  散射条目 — 描述一个读取请求
 * ======================================================================== */
#pragma pack(push, 8)
typedef struct _HV_SCATTER_ENTRY {
    ULONG64 GuestVa;       /* 目标进程虚拟地址 */
    ULONG32 Size;           /* 读取大小 (1 ~ 4096) */
    ULONG32 OutputOffset;   /* 在输出缓冲区中的偏移 */
    ULONG32 Status;         /* [OUT] VMM 填写: 0=成功 */
    ULONG32 Reserved;
} HV_SCATTER_ENTRY, *PHV_SCATTER_ENTRY;
#pragma pack(pop)
/* sizeof = 24, 512条 = 12KB ≈ 3 pages */

/* ========================================================================
 *  批量上下文 — Guest 填写, VMM 读取并执行
 * ======================================================================== */
#pragma pack(push, 8)
typedef struct _HV_BATCH_CONTEXT {
    ULONG64 TargetCr3;       /* 目标进程 CR3 */
    ULONG32 EntryCount;      /* 条目数 (1 ~ HV_BATCH_MAX_ENTRIES) */
    ULONG32 TotalOutputSize; /* 输出缓冲区总大小 */
    ULONG64 EntriesPa;       /* 散射表物理地址 */
    ULONG64 OutputPa;        /* 输出缓冲区物理地址 */
    ULONG32 SuccessCount;    /* [OUT] 成功条目数 */
    volatile LONG Status;    /* [OUT] 0=OK, -1=部分失败 */
} HV_BATCH_CONTEXT, *PHV_BATCH_CONTEXT;
#pragma pack(pop)

/* ========================================================================
 *  CE (R3) → DBKKernel (R0) IOCTL 结构
 * ======================================================================== */
#pragma pack(push, 1)
typedef struct _BATCH_READ_ENTRY {
    ULONG64 Address;        /* 目标虚拟地址 */
    ULONG32 Size;           /* 读取大小 (max 4096) */
} BATCH_READ_ENTRY, *PBATCH_READ_ENTRY;

typedef struct _BATCH_READ_INPUT {
    ULONG64 ProcessID;
    ULONG32 Count;          /* 条目数 */
    ULONG32 Reserved;
    /* 紧跟 BATCH_READ_ENTRY Entries[Count] */
} BATCH_READ_INPUT, *PBATCH_READ_INPUT;

typedef struct _BATCH_READ_OUTPUT {
    ULONG32 SuccessCount;
    ULONG32 TotalSize;      /* 后续数据总字节数 */
    /* 紧跟 Data[TotalSize] */
} BATCH_READ_OUTPUT, *PBATCH_READ_OUTPUT;
#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif /* HV_BATCH_READ_H */
