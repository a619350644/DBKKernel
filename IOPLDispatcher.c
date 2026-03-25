#pragma warning( disable: 4100 4101 4103 4189)


#include "IOPLDispatcher.h"
#include "DBKFunc.h"
#include "DBKDrvr.h"

/* [FIX-v7] MmCopyMemory 声明 — CE 的 WDK 头文件可能没有包含 */
#ifndef MM_COPY_MEMORY_PHYSICAL
#define MM_COPY_MEMORY_PHYSICAL 0x1
#endif

#ifndef MM_COPY_MEMORY_VIRTUAL
#define MM_COPY_MEMORY_VIRTUAL  0x2
#endif
static HANDLE  g_hSvmDev = NULL;
static BOOLEAN g_SvmDevOpened = FALSE;
typedef union _MM_COPY_ADDRESS {
	PVOID            VirtualAddress;
	PHYSICAL_ADDRESS PhysicalAddress;
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;

NTSYSAPI NTSTATUS NTAPI MmCopyMemory(
	PVOID           TargetAddress,
	MM_COPY_ADDRESS SourceAddress,
	SIZE_T          NumberOfBytes,
	ULONG           Flags,
	PSIZE_T         NumberOfBytesTransferred
);


#include "memscan.h"

#include "deepkernel.h"

#include "processlist.h"
#include "threads.h"

#include "interruptHook.h"
#include "debugger.h"

#include "vmxhelper.h"
#include "vmxoffload.h"
#include "ultimap.h"
#include "ultimap2.h"

#include "SvmBridge.h"  /* [NEW] SvmDebug bridge for handle elevation */
#include "HvBatchRead.h" /* [NEW] 批量散射读取共享定义 */
#include "HvMemBridge.h" /* [v19] VMEXIT 写入: HvBridge_WriteProcessMemory */

extern NTSTATUS HvBatchRead_Dispatch(
	PVOID SystemBuffer,
	ULONG InputLength,
	ULONG OutputLength,
	PULONG_PTR BytesReturned);

extern BOOLEAN HvBatchRead_SingleRead(ULONG64 pid, ULONG64 address, PVOID output, ULONG32 size);

/* ========================================================================
 * [TRACE] 一次性路径追踪宏 — 每个调用点只打印一次, 确认链路是否走通
 * ======================================================================== */
#define SVM_TRACE_ONCE(tag, msg) do { \
	static volatile LONG _traced = 0; \
	if (InterlockedCompareExchange(&_traced, 1, 0) == 0) { \
		DbgPrint("[SVM-TRACE] [%s] %s\n", tag, msg); \
	} \
} while(0)

#define SVM_TRACE_ONCE_V(tag, fmt, ...) do { \
	static volatile LONG _traced = 0; \
	if (InterlockedCompareExchange(&_traced, 1, 0) == 0) { \
		DbgPrint("[SVM-TRACE] [%s] " fmt "\n", tag, __VA_ARGS__); \
	} \
} while(0)

 /* ========================================================================
  * 隐身内存引擎 — 直接内联在 IOPLDispatcher.c 中, 不依赖外部文件
  *
  * 核心原理: 所有物理内存读取使用 MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)
  *   - 不调用 MmGetVirtualForPhysical (旧代码根因: 读到 CE 自己的页表)
  *   - 不调用 MmMapIoSpace (ACE 检测系统 PTE 分配模式)
  *   - 不受当前进程上下文影响 (修复 Memory View 错误内存)
  *
  * CR3 掩码: 0x000FFFFFFFFFF000 只保留 bit12-51
  *   - 旧代码 ~0xFFF 保留 bit63(NOFLUSH) 导致物理地址错误
  *
  * KVAS 回退: 先用 +0x28, 失败时回退 +0x280
  * ======================================================================== */

#define STEALTH_CR3_PA_MASK      0x000FFFFFFFFFF000ULL
#define STEALTH_PT_ENTRIES       512
#define STEALTH_CR3_CACHE_SIZE   8
#define STEALTH_EPROCESS_DTB     0x28
#define STEALTH_EPROCESS_UDTTB   0x280

  /* ---- 物理内存读取原语 ---- */
static __forceinline BOOLEAN StealthReadPhysical(UINT64 Pa, PVOID Out, SIZE_T Len)
{
	MM_COPY_ADDRESS src;
	SIZE_T done = 0;
	src.PhysicalAddress.QuadPart = (LONGLONG)Pa;
	return NT_SUCCESS(MmCopyMemory(Out, src, Len, MM_COPY_MEMORY_PHYSICAL, &done))
		&& (done == Len);
}

/* ---- 页表页缓存 ---- */
typedef struct {
	UINT64  BasePa;
	UINT64  Entries[STEALTH_PT_ENTRIES];
	BOOLEAN Valid;
} StealthLevelCache;

typedef struct {
	StealthLevelCache Pml4, Pdpt, Pd, Pt;
	UINT64 Cr3;
} StealthPtCache;

static StealthPtCache g_PtCache = { 0 };

static void StealthResetCache(void) {
	g_PtCache.Pml4.Valid = FALSE;
	g_PtCache.Pdpt.Valid = FALSE;
	g_PtCache.Pd.Valid = FALSE;
	g_PtCache.Pt.Valid = FALSE;
	g_PtCache.Cr3 = 0;
}

static UINT64 StealthCachedPte(StealthLevelCache* c, UINT64 tblPa, UINT64 idx)
{
	UINT64 base = tblPa & ~0xFFFULL;
	if (c->Valid && c->BasePa == base)
		return c->Entries[idx & 0x1FF];
	if (!StealthReadPhysical(base, c->Entries, STEALTH_PT_ENTRIES * sizeof(UINT64))) {
		c->Valid = FALSE;
		return 0;
	}
	c->BasePa = base;
	c->Valid = TRUE;
	return c->Entries[idx & 0x1FF];
}

/* ---- CR3 缓存 ---- */
typedef struct {
	UINT64 Pid, Cr3, UserCr3, Tick;
} StealthCr3Entry;

static StealthCr3Entry g_Cr3Cache[STEALTH_CR3_CACHE_SIZE] = { 0 };

static void StealthReadCr3(UINT64 pid, UINT64* cr3, UINT64* ucr3)
{
	PEPROCESS p = NULL;
	*cr3 = *ucr3 = 0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)pid, &p)) || !p) return;
	*cr3 = *(PUINT64)((PUCHAR)p + STEALTH_EPROCESS_DTB) & STEALTH_CR3_PA_MASK;
	*ucr3 = *(PUINT64)((PUCHAR)p + STEALTH_EPROCESS_UDTTB) & STEALTH_CR3_PA_MASK;
	ObDereferenceObject(p);
}

static UINT64 StealthGetCr3(UINT64 pid)
{
	LARGE_INTEGER tick;
	int i, lru = 0;
	UINT64 oldest = (UINT64)-1, cr3, ucr3;

	if (!pid) return 0;
	KeQueryTickCount(&tick);
	for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++) {
		if (g_Cr3Cache[i].Pid == pid && g_Cr3Cache[i].Cr3) {
			g_Cr3Cache[i].Tick = (UINT64)tick.QuadPart;
			return g_Cr3Cache[i].Cr3;
		}
	}
	StealthReadCr3(pid, &cr3, &ucr3);
	if (!cr3) return 0;
	for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++) {
		if (!g_Cr3Cache[i].Pid) { lru = i; break; }
		if (g_Cr3Cache[i].Tick < oldest) { oldest = g_Cr3Cache[i].Tick; lru = i; }
	}
	g_Cr3Cache[lru].Pid = pid;
	g_Cr3Cache[lru].Cr3 = cr3;
	g_Cr3Cache[lru].UserCr3 = ucr3;
	g_Cr3Cache[lru].Tick = (UINT64)tick.QuadPart;
	return cr3;
}

static void StealthInvalidateCr3(UINT64 pid)
{
	int i;
	for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
		if (g_Cr3Cache[i].Pid == pid) { g_Cr3Cache[i].Pid = 0; g_Cr3Cache[i].Cr3 = 0; }
}

static UINT64 StealthGetUserCr3(UINT64 pid)
{
	int i;
	for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
		if (g_Cr3Cache[i].Pid == pid) return g_Cr3Cache[i].UserCr3;
	StealthGetCr3(pid);
	for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
		if (g_Cr3Cache[i].Pid == pid) return g_Cr3Cache[i].UserCr3;
	return 0;
}

/* ---- VA → PA 翻译 (四级缓存) ---- */
static UINT64 StealthTranslateVaInternal(UINT64 cr3, UINT64 va)
{
	UINT64 e;
	if (g_PtCache.Cr3 != cr3) { StealthResetCache(); g_PtCache.Cr3 = cr3; }

	e = StealthCachedPte(&g_PtCache.Pml4, cr3 & ~0xFFFULL, (va >> 39) & 0x1FF);
	if (!(e & 1)) return 0;
	e = StealthCachedPte(&g_PtCache.Pdpt, e & STEALTH_CR3_PA_MASK, (va >> 30) & 0x1FF);
	if (!(e & 1)) return 0;
	if (e & (1ULL << 7)) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
	e = StealthCachedPte(&g_PtCache.Pd, e & STEALTH_CR3_PA_MASK, (va >> 21) & 0x1FF);
	if (!(e & 1)) return 0;
	if (e & (1ULL << 7)) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
	e = StealthCachedPte(&g_PtCache.Pt, e & STEALTH_CR3_PA_MASK, (va >> 12) & 0x1FF);
	if (!(e & 1)) return 0;
	return (e & STEALTH_CR3_PA_MASK) | (va & 0xFFF);
}

/* 带 KVAS 回退的翻译 */
static UINT64 StealthTranslateVa(UINT64 pid, UINT64 cr3, UINT64 va)
{
	UINT64 pa = StealthTranslateVaInternal(cr3, va);
	if (pa) return pa;
	/* 用户空间地址翻译失败 → 尝试 UserDirectoryTableBase (KVAS) */
	if (va < 0x800000000000ULL) {
		UINT64 ucr3 = StealthGetUserCr3(pid);
		if (ucr3 && ucr3 != cr3) {
			StealthResetCache();
			pa = StealthTranslateVaInternal(ucr3, va);
			if (pa) {
				/* 后续直接用 UserCr3 */
				int i;
				for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
					if (g_Cr3Cache[i].Pid == pid) { g_Cr3Cache[i].Cr3 = ucr3; break; }
				return pa;
			}
		}
		StealthInvalidateCr3(pid);
	}
	return 0;
}

/* ---- 进程内存读取 (物理直读 + attach 兜底) ----
 *
 * [v18] 批量混合读取引擎 — 两遍扫描:
 *   Pass 1: 逐页物理直读 (MmCopyMemory), 记录 paged-out 失败页
 *   Pass 2: 一次 KeStackAttachProcess, 批量读取所有失败页, 一次 detach
 *
 * 优化: 消除 per-page attach/detach 开销
 *   旧方案: N 个 paged-out 页 = N 次 attach + N 次 detach
 *   新方案: N 个 paged-out 页 = 1 次 attach + 1 次 detach
 */
#define STEALTH_MAX_FAIL_ENTRIES 256

typedef struct {
	ULONG  Offset;    /* outBuf 中的偏移 */
	UINT64 Va;        /* 目标虚拟地址 */
	ULONG  Chunk;     /* 字节数 */
} StealthFailEntry;

static BOOLEAN StealthDirectRead(UINT64 pid, UINT64 addr, PVOID outBuf, ULONG size)
{
	UINT64 cr3, va, pa;
	PUCHAR dst;
	ULONG done, rem, chunk;
	PEPROCESS proc = NULL;
	BOOLEAN anyRead = FALSE;
	StealthFailEntry failList[STEALTH_MAX_FAIL_ENTRIES];
	ULONG failCount = 0;

	if (!size || !outBuf) return FALSE;

	/* [FIX] 每次读取前重置页表缓存 + CR3 缓存
	 * 问题: StealthTranslateVa 的 KVAS 回退会把 g_Cr3Cache 中的 CR3
	 *       替换为 UserDirectoryTableBase (+0x280), 在 AMD 上这通常是无效值。
	 *       First Scan 期间替换了 → Next Scan 用错误 CR3 → 翻译全失败 → Found:0
	 * 修复: 同时清除 g_PtCache 和当前 pid 的 CR3 缓存, 强制每次重新读取 */
	StealthResetCache();
	StealthInvalidateCr3(pid);

	cr3 = StealthGetCr3(pid);
	if (!cr3) return FALSE;

	/* 获取 PEPROCESS 供 attach fallback 使用 */
	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)pid, &proc)) || !proc)
		proc = NULL;

	/* === Pass 1: 逐页物理直读, 记录失败页 === */
	dst = (PUCHAR)outBuf; va = addr; done = 0;
	while (done < size) {
		rem = (ULONG)(0x1000 - (va & 0xFFF));
		chunk = size - done;
		if (chunk > rem) chunk = rem;

		BOOLEAN ok = FALSE;

		pa = StealthTranslateVa(pid, cr3, va);
		if (pa && StealthReadPhysical(pa, dst + done, chunk))
			ok = TRUE;

		if (!ok) {
			/* 记录失败页, 稍后批量 attach 处理 */
			if (failCount < STEALTH_MAX_FAIL_ENTRIES) {
				failList[failCount].Offset = done;
				failList[failCount].Va = va;
				failList[failCount].Chunk = chunk;
				failCount++;
			}
			else {
				/* failList 满, 填零 */
				RtlZeroMemory(dst + done, chunk);
			}
		}
		else {
			anyRead = TRUE;
		}

		done += chunk; va += chunk;
		cr3 = StealthGetCr3(pid);
		if (!cr3) break;
	}

	/* === Pass 2: 一次 attach, 批量读取所有 paged-out 页 === */
	if (failCount > 0 && proc) {
		KAPC_STATE apc;
		UCHAR tmpBuf[0x1000];
		ULONG i;

		KeStackAttachProcess(proc, &apc);

		for (i = 0; i < failCount; i++) {
			__try {
				ULONG c = failList[i].Chunk;
				if (c > 0x1000) c = 0x1000;
				RtlCopyMemory(tmpBuf, (PVOID)(ULONG_PTR)failList[i].Va, c);
				RtlCopyMemory(dst + failList[i].Offset, tmpBuf, c);
				anyRead = TRUE;
				failList[i].Chunk = 0; /* 标记成功 */
			}
			__except (1) {
				/* 此页仍然失败, 保留非零 Chunk 供后续填零 */
			}
		}

		KeUnstackDetachProcess(&apc);
	}

	/* === 仍然失败的页填零 === */
	{
		ULONG i;
		for (i = 0; i < failCount; i++) {
			if (failList[i].Chunk != 0)
				RtlZeroMemory(dst + failList[i].Offset, failList[i].Chunk);
		}
	}

	if (proc) ObDereferenceObject(proc);
	return anyRead;
}

/* ---- 进程内存写入 (attach + 内核栈缓冲区中转) ----
 *
 * [v17] 写入始终走 attach 路径:
 *   - 物理写需要 MmMapIoSpace → PFN 污染 → BSOD 0x1A
 *   - 写入频率远低于读取, attach 开销可接受
 *   - 内核栈缓冲区中转: 先把数据拷到 tmpBuf, attach 后写入目标 VA
 */
static BOOLEAN StealthDirectWrite(UINT64 pid, UINT64 addr, PVOID data, ULONG size)
{
	PUCHAR src;
	ULONG done, rem, chunk;
	PEPROCESS proc = NULL;
	BOOLEAN anyWrite = FALSE;

	if (!size || !data) return FALSE;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)pid, &proc)) || !proc)
		return FALSE;

	src = (PUCHAR)data; done = 0;
	while (done < size) {
		UINT64 va = addr + done;
		rem = (ULONG)(0x1000 - (va & 0xFFF));
		chunk = size - done;
		if (chunk > rem) chunk = rem;

		/* 先拷到内核栈缓冲区 (调用者地址空间) */
		UCHAR tmpBuf[0x1000];
		RtlCopyMemory(tmpBuf, src + done, chunk);

		/* attach 后写入目标 VA */
		KAPC_STATE apc;
		KeStackAttachProcess(proc, &apc);
		__try {
			RtlCopyMemory((PVOID)(ULONG_PTR)va, tmpBuf, chunk);
			anyWrite = TRUE;
		}
		__except (1) {}
		KeUnstackDetachProcess(&apc);

		done += chunk;
	}

	ObDereferenceObject(proc);
	return anyWrite;
}

/* ---- 页保护查询 ---- */
static DWORD StealthPteToProtect(UINT64 pte)
{
	DWORD rw, nx;
	if (!(pte & 1)) return 0;
	if (!(pte & 4)) return 0; /* Supervisor → skip */
	rw = (pte & 2) ? 1 : 0;
	nx = (pte & (1ULL << 63)) ? 1 : 0;
	if (rw && !nx) return 0x40; /* PAGE_EXECUTE_READWRITE */
	if (rw && nx) return 0x04; /* PAGE_READWRITE */
	if (!rw && !nx) return 0x20; /* PAGE_EXECUTE_READ */
	return 0x02;                  /* PAGE_READONLY */
}

static DWORD StealthGetPageProtect(UINT64 cr3, UINT64 va, PUINT64 skip)
{
	UINT64 e;
	if (skip) *skip = 0x1000;
	if (g_PtCache.Cr3 != cr3) { StealthResetCache(); g_PtCache.Cr3 = cr3; }

	e = StealthCachedPte(&g_PtCache.Pml4, cr3 & ~0xFFFULL, (va >> 39) & 0x1FF);
	if (!(e & 1)) { if (skip) *skip = (((va >> 39) + 1) << 39) - va; return 0; }

	e = StealthCachedPte(&g_PtCache.Pdpt, e & STEALTH_CR3_PA_MASK, (va >> 30) & 0x1FF);
	if (!(e & 1)) { if (skip) *skip = (((va >> 30) + 1) << 30) - va; return 0; }
	if (e & (1ULL << 7)) { if (skip) *skip = 1ULL << 30; return StealthPteToProtect(e); }

	e = StealthCachedPte(&g_PtCache.Pd, e & STEALTH_CR3_PA_MASK, (va >> 21) & 0x1FF);
	if (!(e & 1)) { if (skip) *skip = (((va >> 21) + 1) << 21) - va; return 0; }
	if (e & (1ULL << 7)) { if (skip) *skip = 1ULL << 21; return StealthPteToProtect(e); }

	e = StealthCachedPte(&g_PtCache.Pt, e & STEALTH_CR3_PA_MASK, (va >> 12) & 0x1FF);
	if (skip) *skip = 0x1000;
	return StealthPteToProtect(e);
}

static BOOLEAN StealthQueryRegion(UINT64 cr3, UINT64 startVa,
	PUINT_PTR outSize, PDWORD outProt, PUINT64 outBase)
{
	UINT64 va, regionStart, maxVa, sk;
	DWORD first, cur;

	va = startVa & ~0xFFFULL;
	maxVa = 0x7FFFFFFF0000ULL;
	if (va >= maxVa) return FALSE;

	/* 获取起始页属性 */
	sk = 0x1000;
	first = StealthGetPageProtect(cr3, va, &sk);

	/* 向后扫描找区域起点 */
	regionStart = va;
	if (va >= 0x1000) {
		UINT64 back = va - 0x1000;
		while (back < va) {
			sk = 0x1000;
			cur = StealthGetPageProtect(cr3, back, &sk);
			if (cur != first) break;
			regionStart = back;
			if (back < 0x1000) break;
			back -= 0x1000;
		}
	}

	/* 向前扫描找区域终点 */
	va = (startVa & ~0xFFFULL) + 0x1000;
	while (va < maxVa) {
		sk = 0x1000;
		cur = StealthGetPageProtect(cr3, va, &sk);
		if (cur != first) break;
		va += sk;
	}
	if (va > maxVa) va = maxVa;

	*outSize = (UINT_PTR)(va - regionStart);
	*outProt = first;
	if (outBase) *outBase = regionStart;
	return (*outSize > 0);
}

/* ---- 辅助: GetPhysAddr / GetProcessCr3 ---- */
static UINT64 StealthGetPhysAddr(UINT64 pid, UINT64 va)
{
	UINT64 cr3 = StealthGetCr3(pid);
	if (!cr3) return 0;
	return StealthTranslateVa(pid, cr3, va);
}

static UINT64 StealthGetProcessCr3(UINT64 pid)
{
	return StealthGetCr3(pid);
}

/* ---- DBKDrvr.c 调用的初始化/清理 (非 static) ---- */
void StealthInit(void)
{
	RtlZeroMemory(&g_PtCache, sizeof(g_PtCache));
	RtlZeroMemory(g_Cr3Cache, sizeof(g_Cr3Cache));
}

void StealthCleanup(void)
{
	/* [FIX-v14] 关闭 IOPLDispatcher 本地的 SvmDebug 设备句柄
	 * 如果不关, SvmDebug 的 IoDeleteDevice 会因引用计数>0 而挂起,
	 * 导致 sc stop SvmDebug 永远卡住 */
	if (g_hSvmDev) {
		ZwClose(g_hSvmDev);
		g_hSvmDev = NULL;
	}
	g_SvmDevOpened = FALSE;

	RtlZeroMemory(&g_PtCache, sizeof(g_PtCache));
	RtlZeroMemory(g_Cr3Cache, sizeof(g_Cr3Cache));
}

/* ---- 本地虚拟内存查询 ----
 *
 * [v19 BUG FIX] 使用 ObOpenObjectByPointer + kernel handle 查询目标进程
 *
 * 旧方式 (v18):
 *   KeStackAttachProcess(target) + ZwQueryVirtualMemory(NtCurrentProcess(), ...)
 *   问题: NPT Hook Fake_NtQueryVirtualMemory 检测到 ProcessHandle == NtCurrentProcess()
 *         && 进程不是 CE (已 attach 到 target) → 触发"自查伪装"代码
 *         → 把 PAGE_EXECUTE_READWRITE 改成 PAGE_READONLY
 *         → CE 看到错误的保护属性 → Memory Viewer 显示 ??? + First Scan 跳过区域
 *
 * 新方式 (v19):
 *   ObOpenObjectByPointer(target) → ZwQueryVirtualMemory(kernelHandle, ...)
 *   NPT Hook 检测到 ProcessHandle 不是 NtCurrentProcess() + 调用者 PID 在保护列表
 *   → 走 CE 外部查询透传路径 → 返回真实保护属性
 */
static NTSTATUS StealthQueryVM(UINT64 pid, UINT64 startVa,
	PUINT64 outBase, PUINT64 outSize, PULONG outProt, PULONG outState, PULONG outType)
{
	PEPROCESS proc = NULL;
	NTSTATUS st;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T retLen = 0;
	HANDLE kernelHandle = NULL;

	st = PsLookupProcessByProcessId((PVOID)(UINT_PTR)pid, &proc);
	if (!NT_SUCCESS(st) || !proc) return STATUS_NOT_FOUND;

	/* [BUG FIX] 使用 kernel handle 替代 KeStackAttachProcess + NtCurrentProcess()
	 * kernel handle 不走 ObRegisterCallbacks, ACE 看不到
	 * 且 NPT Hook 不会触发"自查伪装" (因为 ProcessHandle != NtCurrentProcess()) */
	st = ObOpenObjectByPointer(
		proc,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_QUERY_INFORMATION,
		*PsProcessType,
		KernelMode,
		&kernelHandle);

	ObDereferenceObject(proc);

	if (!NT_SUCCESS(st) || !kernelHandle) {
		DbgPrint("[QVM] ObOpenObjectByPointer failed: 0x%X pid=%llu\n", st, pid);
		return st;
	}

	st = ZwQueryVirtualMemory(kernelHandle, (PVOID)(ULONG_PTR)startVa,
		MemoryBasicInformation, &mbi, sizeof(mbi), &retLen);

	ZwClose(kernelHandle);

	if (NT_SUCCESS(st)) {
		if (outBase)  *outBase = (UINT64)mbi.BaseAddress;
		if (outSize)  *outSize = (UINT64)mbi.RegionSize;
		if (outProt)  *outProt = mbi.Protect;
		if (outState) *outState = mbi.State;
		if (outType)  *outType = mbi.Type;
	}
	return st;
}

/* ========================================================================
 * 隐身内存引擎 — 结束
 * ========================================================================*/

 /* ========================================================================
  * SvmDebug IOCTL 读写 — 通过 SvmDebug 驱动的 KeStackAttachProcess 读写
  *
  * 为什么不用本地物理页表遍历 (StealthDirectRead):
  *   物理页表遍历无法处理 paged-out 页面 (PTE Present=0 → 返回全零)
  *   这就是 Memory View 显示全零/错误数据的根因
  *
  * 为什么通过 SvmDebug 安全:
  *   SvmDebug 在自己的系统线程上下文中调用 KeStackAttachProcess
  *   ACE 看到的调用栈是 SvmDebug, 不是 CE 的 DBKKernel
  *   SvmDebug 的 DeepHook 已 Hook KiStackAttachProcess, 自身调用被放行
  * ======================================================================== */

#define SVM_IOCTL_HV_READ  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SVM_IOCTL_HV_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _SVM_MEM_REQ {
	UINT64 TargetPid;
	UINT64 Address;
	UINT64 Size;
	UINT64 BufferAddress;
} SVM_MEM_REQ;
#pragma pack(pop)



static BOOLEAN SvmEnsureDevice(void)
{
	UNICODE_STRING devName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	NTSTATUS st;
	static LONG retries = 0;

	if (g_hSvmDev) return TRUE;
	if (g_SvmDevOpened && retries >= 3) return FALSE;

	RtlInitUnicodeString(&devName, L"\\Device\\SvmDebug");
	InitializeObjectAttributes(&oa, &devName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	st = ZwOpenFile(&g_hSvmDev, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
	g_SvmDevOpened = TRUE;
	if (!NT_SUCCESS(st)) { g_hSvmDev = NULL; InterlockedIncrement(&retries); return FALSE; }
	return TRUE;
}

static BOOLEAN SvmHvRead(UINT64 pid, UINT64 addr, PVOID outBuf, ULONG size)
{
	IO_STATUS_BLOCK iosb;
	SVM_MEM_REQ req;
	PVOID kbuf;
	NTSTATUS st;

	if (!SvmEnsureDevice() || !size) return FALSE;

	kbuf = ExAllocatePoolWithTag(NonPagedPool, size, 'SvRd');
	if (!kbuf) return FALSE;
	RtlZeroMemory(kbuf, size);

	req.TargetPid = pid;
	req.Address = addr;
	req.Size = (UINT64)size;
	req.BufferAddress = (UINT64)kbuf;

	st = ZwDeviceIoControlFile(g_hSvmDev, NULL, NULL, NULL, &iosb,
		SVM_IOCTL_HV_READ, &req, sizeof(req), NULL, 0);

	if (NT_SUCCESS(st))
		RtlCopyMemory(outBuf, kbuf, size);

	ExFreePoolWithTag(kbuf, 'SvRd');
	return NT_SUCCESS(st);
}

static BOOLEAN SvmHvWrite(UINT64 pid, UINT64 addr, PVOID data, ULONG size)
{
	IO_STATUS_BLOCK iosb;
	SVM_MEM_REQ req;
	PVOID kbuf;
	NTSTATUS st;

	if (!SvmEnsureDevice() || !size) return FALSE;

	kbuf = ExAllocatePoolWithTag(NonPagedPool, size, 'SvWr');
	if (!kbuf) return FALSE;
	RtlCopyMemory(kbuf, data, size);

	req.TargetPid = pid;
	req.Address = addr;
	req.Size = (UINT64)size;
	req.BufferAddress = (UINT64)kbuf;

	st = ZwDeviceIoControlFile(g_hSvmDev, NULL, NULL, NULL, &iosb,
		SVM_IOCTL_HV_WRITE, &req, sizeof(req), NULL, 0);

	ExFreePoolWithTag(kbuf, 'SvWr');
	return NT_SUCCESS(st);
}

/* ========================================================================
 * SvmDebug IOCTL 读写 — 结束
 * ======================================================================== */

UINT64 PhysicalMemoryRanges = 0; //initialized once, and used thereafter. If the user adds/removes ram at runtime, screw him and make him the reload the driver
UINT64 PhysicalMemoryRangesListSize = 0;

#if (NTDDI_VERSION >= NTDDI_VISTA)
PVOID DRMHandle = NULL;
PEPROCESS DRMProcess = NULL;
PEPROCESS DRMProcess2 = NULL;
#endif

typedef PCHAR(*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);
GET_PROCESS_IMAGE_NAME PsGetProcessImageFileName;


/*
typedef struct
{
	int listcount;
	char cpunrs[255];
} CPULISTFILLSTRUCT, *PCPULISTFILLSTRUCT;

VOID GetCPUIDS_all(PCPULISTFILLSTRUCT p)
{
	DbgPrint("GetCPUIDS_all(for cpu %d)\n", cpunr());
	if (p->listcount<255)
	{
		p->cpunrs[p->listcount]=cpunr();
		p->listcount++;
	}
}
*/

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);



void mykapc2(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	ULONG_PTR iswow64;
	ExFreePool(Apc);
	DbgPrint("My second kernelmode apc!!!!\n");
	DbgPrint("SystemArgument1=%x\n", *(PULONG)SystemArgument1);
	DbgPrint("SystemArgument2=%x\n", *(PULONG)SystemArgument2);

	if (ZwQueryInformationProcess(ZwCurrentProcess(), ProcessWow64Information, &iswow64, sizeof(iswow64), NULL) == STATUS_SUCCESS)
	{
#if (NTDDI_VERSION >= NTDDI_VISTA)	
		if (iswow64)
		{
			DbgPrint("WOW64 apc");
			PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);
		}
#endif
	}

}

void nothing2(PVOID arg1, PVOID arg2, PVOID arg3)
{

	return;
}

void mykapc(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	//kernelmode apc, always gets executed
	PKAPC      kApc;
	LARGE_INTEGER Timeout;

	kApc = ExAllocatePool(NonPagedPool, sizeof(KAPC));

	ExFreePool(Apc);

	DbgPrint("My kernelmode apc!!!!(irql=%d)\n", KeGetCurrentIrql());

	DbgPrint("NormalRoutine=%p\n", *(PUINT_PTR)NormalRoutine);
	DbgPrint("NormalContext=%p\n", *(PUINT_PTR)NormalContext);
	DbgPrint("SystemArgument1=%p\n", *(PUINT_PTR)SystemArgument1);
	DbgPrint("SystemArgument2=%p\n", *(PUINT_PTR)SystemArgument2);



	KeInitializeApc(kApc,
		(PKTHREAD)PsGetCurrentThread(),
		0,
		(PKKERNEL_ROUTINE)mykapc2,
		NULL,
		(PKNORMAL_ROUTINE) * (PUINT_PTR)SystemArgument1,
		UserMode,
		(PVOID) * (PUINT_PTR)NormalContext
	);

	KeInsertQueueApc(kApc, (PVOID) * (PUINT_PTR)SystemArgument1, (PVOID) * (PUINT_PTR)SystemArgument2, 0);


	//wait in usermode (so interruptable by a usermode apc)
	Timeout.QuadPart = 0;
	KeDelayExecutionThread(UserMode, TRUE, &Timeout);

	return;
}

void nothing(PVOID arg1, PVOID arg2, PVOID arg3)
{
	return;
}


void CreateRemoteAPC(ULONG threadid, PVOID addresstoexecute)
{

	PKTHREAD   kThread;
	PKAPC      kApc;

	kApc = ExAllocatePool(NonPagedPool, sizeof(KAPC));

	kThread = (PKTHREAD)getPEThread(threadid);
	DbgPrint("(PVOID)KThread=%p\n", kThread);
	DbgPrint("addresstoexecute=%p\n", addresstoexecute);


	KeInitializeApc(kApc,
		kThread,
		0,
		(PKKERNEL_ROUTINE)mykapc,
		NULL,
		(PKNORMAL_ROUTINE)nothing,
		KernelMode,
		0
	);

	KeInsertQueueApc(kApc, addresstoexecute, addresstoexecute, 0);
}

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


#if (NTDDI_VERSION >= NTDDI_VISTA)
OB_PREOP_CALLBACK_STATUS ThreadPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	if (DRMProcess == NULL)
		return OB_PREOP_SUCCESS;

	if (PsGetCurrentProcess() == DRMProcess)
		return OB_PREOP_SUCCESS;

	if (OperationInformation->ObjectType == *PsThreadType)
	{
		if ((PsGetProcessId(DRMProcess) == PsGetThreadProcessId(OperationInformation->Object)) || ((DRMProcess2) && (PsGetProcessId(DRMProcess2) == PsGetThreadProcessId(OperationInformation->Object))))
		{
			//probably block it

			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				//create handle			

				ACCESS_MASK da = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

				DbgPrint("PID %d opened a handle to the a CE thread with access mask %x", PsGetCurrentProcessId(), da);

				da = da & (THREAD_SET_LIMITED_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);

				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;// da;
			}
			else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				//duplicate handle
				ACCESS_MASK da = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

				DbgPrint("PID %d duplicated a handle to a CE thread with access mask %x", PsGetCurrentProcessId(), da);

				da = da & (THREAD_SET_LIMITED_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;// da;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}


VOID ThreadPostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	//DbgPrint("ProcessPostCallback");
}


OB_PREOP_CALLBACK_STATUS ProcessPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	if (DRMProcess == NULL)
		return OB_PREOP_SUCCESS;

	//if (PsGetCurrentProcess() == DRMProcess)
	//	return OB_PREOP_SUCCESS;

	if (OperationInformation->ObjectType == *PsProcessType)
	{
		if ((OperationInformation->Object == DRMProcess) || (OperationInformation->Object == DRMProcess2))
		{
			//probably block it

			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				//create handle			

				ACCESS_MASK da = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

				DbgPrint("PID %d(%p) opened a handle to the CE process(%p) with access mask %x", PsGetCurrentProcessId(), PsGetCurrentProcess(), DRMProcess, da);

				da = da & (PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME);

				//da = da & PROCESS_SUSPEND_RESUME;

				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;// da;
			}
			else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				//duplicate handle
				ACCESS_MASK da = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

				DbgPrint("PID %d(%p) opened a handle to the CE process(%p) with access mask %x", PsGetCurrentProcessId(), PsGetCurrentProcess(), DRMProcess, da);


				da = da & (PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME);

				//da = da & PROCESS_SUSPEND_RESUME;

				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;// da;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}


VOID ProcessPostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	//DbgPrint("ProcessPostCallback");
}
#endif


BOOL DispatchIoctlDBVM(IN PDEVICE_OBJECT DeviceObject, ULONG IoControlCode, PVOID lpInBuffer, DWORD nInBufferSize, PVOID lpOutBuffer, DWORD nOutBufferSize, PDWORD lpBytesReturned)
/*
Called if dbvm has loaded the driver. Use this to setup a fake irp
*/
{
	//allocate a in and out buffer
	//setup a fake IRP
	IRP FakeIRP;
	BOOL r;
	PVOID buffer;
	buffer = ExAllocatePool(PagedPool, max(nInBufferSize, nOutBufferSize));
	RtlCopyMemory(buffer, lpInBuffer, nInBufferSize);


	DbgPrint("DispatchIoctlDBVM\n");

	FakeIRP.AssociatedIrp.SystemBuffer = buffer;
	FakeIRP.Flags = IoControlCode; //(ab)using an unused element

	r = DispatchIoctl(DeviceObject, &FakeIRP) == STATUS_SUCCESS;


	RtlCopyMemory(lpOutBuffer, buffer, nOutBufferSize);

	ExFreePool(buffer);

	return r;
}

NTSTATUS DispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	PIO_STACK_LOCATION     irpStack = NULL;
	LUID sedebugprivUID;
	ULONG IoControlCode;

	if (!loadedbydbvm)
	{
		irpStack = IoGetCurrentIrpStackLocation(Irp);
		IoControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	}
	else
		IoControlCode = Irp->Flags;

	//DbgPrint("DispatchIoctl. IoControlCode=%x\n", IoControlCode);
#ifdef TOBESIGNED
	sedebugprivUID.LowPart = SE_DEBUG_PRIVILEGE;
	sedebugprivUID.HighPart = 0;

	if (SeSinglePrivilegeCheck(sedebugprivUID, UserMode) == FALSE)
	{
		DbgPrint("DispatchIoctl called by a process without SeDebugPrivilege");
		return STATUS_UNSUCCESSFUL;
	}
#endif



	switch (IoControlCode)
	{

	case IOCTL_CE_READMEMORY:
		/* [DIAG] 无条件打印 - 每次进入 IOCTL_CE_READMEMORY 都会输出 */
		DbgPrint("[DIAG] IOCTL_CE_READMEMORY entry, SvmActive=%d\n",
			(int)SvmBridge_IsActive());

		__try
		{
			struct input
			{
				UINT64 processid;
				UINT64 startaddress;
				WORD bytestoread;
			} *pinp;
			static volatile LONG s_readDiag = 0;
			static volatile LONG s_vmexitOkCount = 0;
			static volatile LONG s_fallbackCount = 0;
			static volatile LONG s_legacyCount = 0;

			pinp = Irp->AssociatedIrp.SystemBuffer;

			{
				LONG diagSeq = InterlockedIncrement(&s_readDiag);
				if (diagSeq <= 20) {
					DbgPrint("[SVM-CE] IOCTL_CE_READMEMORY #%d: PID=%llu addr=0x%llX size=%u SvmActive=%d\n",
						diagSeq, pinp->processid, pinp->startaddress, (UINT)pinp->bytestoread,
						(int)SvmBridge_IsActive());
				}
			}

			/* [v19] 所有内存读取强制走 VMEXIT 路径, 零 Guest R0 内存操作
			 * HvBatchRead_SingleRead: 1次 CPUID VMEXIT → VMM Host 物理直读
			 * 完全不在 Guest R0 留下任何 MmCopyMemory/KeStackAttachProcess 痕迹
			 *
			 * 如果 VMEXIT 失败 (页面被换出/未映射), 填零而非回退到 Guest R0
			 * 原因: KeStackAttachProcess/MmCopyMemory 会在 Guest R0 留下调用栈痕迹
			 * 页面换出时 Memory Viewer 显示 00 是可接受的 (等同于未映射)
			 */
			if (SvmBridge_IsActive())
			{
				SVM_TRACE_ONCE("READMEM", ">>> Entering StealthDirectRead path (MmCopyMemory + attach fallback)");

				/* [FIX] 使用 StealthDirectRead 替代 HvBatchRead_SingleRead
				 *
				 * 为什么换掉 HvBatchRead (CPUID VMEXIT):
				 *   HvBatchRead_SingleRead → CPUID(0x41414151) → VMM 物理直读
				 *   但日志中从未出现过 [BatchRead] 前缀的打印
				 *   → 要么 VMM 没有处理该 CPUID leaf, 要么 DoBatchRead 初始化失败
				 *   → 读取全部返回零 → First Scan Found:0
				 *
				 * StealthDirectRead 的优势:
				 *   1. MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) 物理直读 — 不走任何 hook
				 *   2. paged-out 页面自动 attach 兜底 — 不丢数据
				 *   3. 已在 IOPLDispatcher.c 中实现并验证
				 */
				UINT64 savedPid = pinp->processid;
				UINT64 savedAddr = pinp->startaddress;
				WORD   savedSize = pinp->bytestoread;

				if (StealthDirectRead(savedPid, savedAddr, pinp, savedSize))
				{
					SVM_TRACE_ONCE("READMEM", "<<< StealthDirectRead SUCCESS");
					ntStatus = STATUS_SUCCESS;
				}
				else
				{
					static volatile LONG s_readFail = 0;
					LONG fCnt = InterlockedIncrement(&s_readFail);
					if (fCnt <= 20 || (fCnt % 5000) == 0) {
						DbgPrint("[SVM-CE] StealthDirectRead FAIL #%d: PID=%llu addr=0x%llX size=%u\n",
							fCnt, savedPid, savedAddr, (UINT)savedSize);
					}
					__try { RtlZeroMemory(pinp, savedSize); }
					__except (1) {}
					ntStatus = STATUS_SUCCESS;
				}
			}
			else
			{
				LONG legCnt = InterlockedIncrement(&s_legacyCount);
				if (legCnt <= 5 || (legCnt % 5000) == 0) {
					DbgPrint("[SVM-CE] LEGACY READ (no SVM) #%d: PID=%llu addr=0x%llX size=%u\n",
						legCnt, pinp->processid, pinp->startaddress, (UINT)pinp->bytestoread);
				}
				ntStatus = ReadProcessMemory((DWORD)pinp->processid, NULL, (PVOID)(UINT_PTR)pinp->startaddress, pinp->bytestoread, pinp) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			}
		}
		__except (1)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
		};

		break;


	case IOCTL_CE_WRITEMEMORY:
		__try
		{
			struct input
			{
				UINT64 processid;
				UINT64 startaddress;
				WORD bytestowrite;
			} *pinp, inp;

			DbgPrint("sizeof(inp)=%d\n", sizeof(inp));
			pinp = Irp->AssociatedIrp.SystemBuffer;

			/* [v19] 所有内存写入也走 VMEXIT 路径
			 * HvBridge_WriteProcessMemory: CPUID(CPUID_HV_MEMORY_OP) → VMEXIT → VMM Host 物理写入
			 * Guest R0 零 MmMapIoSpace / KeStackAttachProcess 痕迹 */
			if (SvmBridge_IsActive())
			{
				static volatile LONG s_writeDiag = 0;
				LONG wCnt = InterlockedIncrement(&s_writeDiag);
				if (wCnt <= 20 || (wCnt % 2000) == 0) {
					DbgPrint("[SVM-CE] WRITE VMEXIT #%d: PID=%llu addr=0x%llX size=%u\n",
						wCnt, pinp->processid, pinp->startaddress, (UINT)pinp->bytestowrite);
				}
				ntStatus = HvBridge_WriteProcessMemory(
					(DWORD)pinp->processid, NULL,
					(PVOID)(UINT_PTR)pinp->startaddress,
					pinp->bytestowrite,
					(PVOID)((UINT_PTR)pinp + sizeof(inp)))
					? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			}
			else
			{
				ntStatus = WriteProcessMemory((DWORD)pinp->processid, NULL, (PVOID)(UINT_PTR)pinp->startaddress, pinp->bytestowrite, (PVOID)((UINT_PTR)pinp + sizeof(inp))) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			}
		}
		__except (1)
		{
			//something went wrong and I don't know what
			ntStatus = STATUS_UNSUCCESSFUL;
		};



		break;


	case IOCTL_CE_OPENPROCESS:
	{
		PEPROCESS selectedprocess = NULL;
		ULONG processid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
		HANDLE ProcessHandle = GetHandleForProcessID((HANDLE)processid);
		struct out
		{
			UINT64 h;
			BYTE   Special;
		} *POutput = Irp->AssociatedIrp.SystemBuffer;


		ntStatus = STATUS_SUCCESS;
		if (ProcessHandle == 0)
		{
			POutput->Special = 0;
			__try
			{
				ProcessHandle = 0;

				if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(processid), &selectedprocess) == STATUS_SUCCESS)
				{
					/* [SVM-FIX] When SvmBridge is active, use OBJ_KERNEL_HANDLE to create
					 * a kernel handle first, then duplicate to user handle.
					 * This bypasses ACE's ObRegisterCallbacks which only strip
					 * access on user-mode handle creation (KernelHandle=TRUE is skipped).
					 *
					 * Original path: ObOpenObjectByPointer(flags=0) creates user handle
					 * -> ACE callback fires -> strips PROCESS_ALL_ACCESS -> error 5
					 *
					 * Fixed path: ObOpenObjectByPointer(OBJ_KERNEL_HANDLE) creates kernel handle
					 * -> ACE callback sees KernelHandle=TRUE -> skips
					 * -> ZwDuplicateObject converts to user handle -> CE gets full access
					 */
					if (SvmBridge_IsActive())
					{
						HANDLE kernelHandle = NULL;
						ntStatus = ObOpenObjectByPointer(
							selectedprocess,
							OBJ_KERNEL_HANDLE,
							NULL,
							PROCESS_ALL_ACCESS,
							*PsProcessType,
							KernelMode,
							&kernelHandle);

						if (NT_SUCCESS(ntStatus) && kernelHandle)
						{
							HANDLE userHandle = NULL;
							ntStatus = ZwDuplicateObject(
								NtCurrentProcess(), kernelHandle,
								NtCurrentProcess(), &userHandle,
								PROCESS_ALL_ACCESS, 0, 0);

							ZwClose(kernelHandle);

							if (NT_SUCCESS(ntStatus) && userHandle)
							{
								ProcessHandle = userHandle;
								DbgPrint("[DBK-SVM] OpenProcess PID %lu: kernel->user handle OK (h=0x%p)\n",
									processid, userHandle);
							}
							else
							{
								DbgPrint("[DBK-SVM] OpenProcess PID %lu: ZwDuplicateObject failed 0x%X\n",
									processid, ntStatus);
							}
						}
						else
						{
							DbgPrint("[DBK-SVM] OpenProcess PID %lu: ObOpenObjectByPointer(KERNEL) failed 0x%X\n",
								processid, ntStatus);
						}
					}
					else
					{
						/* Original path when SVM is not active */
						ntStatus = ObOpenObjectByPointer(
							selectedprocess,
							0,
							NULL,
							PROCESS_ALL_ACCESS,
							*PsProcessType,
							KernelMode,
							&ProcessHandle);
					}
				}
			}
			__except (1)
			{
				ntStatus = STATUS_UNSUCCESSFUL;
			}
		}
		else
		{
			//DbgPrint("ProcessHandle=%x", (int)ProcessHandle);
			POutput->Special = 1;
		}

		if (selectedprocess)
		{
			ObDereferenceObject(selectedprocess);
		}

		POutput->h = (UINT64)ProcessHandle;
		break;
	}


	case IOCTL_CE_OPENTHREAD:
	{
		HANDLE ThreadHandle;
		CLIENT_ID ClientID;
		OBJECT_ATTRIBUTES ObjectAttributes;

		RtlZeroMemory(&ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));

		ntStatus = STATUS_SUCCESS;

		ClientID.UniqueProcess = 0;
		ClientID.UniqueThread = (HANDLE)(UINT_PTR) * (PULONG)Irp->AssociatedIrp.SystemBuffer;
		ThreadHandle = 0;

		__try
		{
			ThreadHandle = 0;
			ntStatus = ZwOpenThread(&ThreadHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientID);
		}
		__except (1)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		*(PUINT64)Irp->AssociatedIrp.SystemBuffer = (UINT64)ThreadHandle;


		break;
	}


	case IOCTL_CE_MAKEWRITABLE:
	{
#ifdef AMD64
		//untill I know how win64 handles paging, not implemented
#else
		struct InputBuf
		{
			UINT64 StartAddress;
			ULONG Size;
			BYTE CopyOnWrite;
		} *PInputBuf;

		PInputBuf = Irp->AssociatedIrp.SystemBuffer;

		ntStatus = MakeWritable((PVOID)(UINT_PTR)PInputBuf->StartAddress, PInputBuf->Size, (PInputBuf->CopyOnWrite == 1)) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
#endif
		break;
	}



	case IOCTL_CE_QUERY_VIRTUAL_MEMORY:
	{
		struct InputBuf
		{
			UINT64 ProcessID;
			UINT64 StartAddress;
		} *PInputBuf;

		struct OutputBuf
		{
			UINT64 length;
			DWORD protection;
		} *POutputBuf;



		UINT_PTR BaseAddress;
		UINT_PTR length = 0;
		BOOL ShowResult = 0;


		ntStatus = STATUS_SUCCESS;
		PInputBuf = Irp->AssociatedIrp.SystemBuffer;
		POutputBuf = Irp->AssociatedIrp.SystemBuffer;


		if (PInputBuf->StartAddress == (UINT64)0x12000)
			ShowResult = 1;


		__try
		{
			BOOLEAN svmHandled = FALSE;
			static volatile LONG s_qvmDiag = 0;

			if (SvmBridge_IsActive())
			{
				SVM_TRACE_ONCE("QVM", ">>> Entering StealthQueryVM path (ZwQueryVirtualMemory + kernel handle)");

				/* [FIX] 使用 StealthQueryVM (ZwQueryVirtualMemory + kernel handle)
				 *
				 * 为什么不能用物理页表遍历 (PhysWalk):
				 *   PhysWalk 只查物理 PTE, 不查 Windows VAD (Virtual Address Descriptor)
				 *   已提交但未映射的页面 (MEM_COMMIT, PTE not present) 显示为 prot=0
				 *   → CE 看到整个地址空间几乎都是 "Free" → First Scan 跳过 → Found:0
				 *
				 * 为什么 StealthQueryVM 现在能工作:
				 *   StealthQueryVM 创建 kernel handle → ZwQueryVirtualMemory
				 *   → NPT Hook Fake_NtQueryVirtualMemory → PATH-B
				 *   → 再次创建 kernel handle (OBJ_KERNEL_HANDLE, 绕过 ObRegisterCallbacks)
				 *   → 调用原始 NtQueryVirtualMemory → 返回正确的 VAD 信息
				 */
				UINT64 qvmBase = 0, qvmSize = 0;
				ULONG  qvmProt = 0, qvmState = 0, qvmType = 0;

				ntStatus = StealthQueryVM(
					PInputBuf->ProcessID,
					PInputBuf->StartAddress,
					&qvmBase, &qvmSize, &qvmProt, &qvmState, &qvmType);

				if (InterlockedIncrement(&s_qvmDiag) <= 30) {
					DbgPrint("[QVM-DIAG] StealthQueryVM: PID=%llu VA=0x%llX -> status=0x%X base=0x%llX size=0x%llX prot=0x%X state=0x%X\n",
						PInputBuf->ProcessID, PInputBuf->StartAddress,
						ntStatus, qvmBase, qvmSize, qvmProt, qvmState, qvmType);
				}

				if (NT_SUCCESS(ntStatus)) {
					BaseAddress = (UINT_PTR)qvmBase;
					length = (UINT_PTR)qvmSize;
					POutputBuf->protection = qvmProt;
					svmHandled = TRUE;

					SVM_TRACE_ONCE_V("QVM", "<<< StealthQueryVM SUCCESS: prot=0x%X size=0x%llX state=0x%X", qvmProt, qvmSize, qvmState);
				}
			}

			/* SVM 未激活 或 物理页表遍历失败 → 回退到原始路径 */
			if (!svmHandled)
			{
				ntStatus = GetMemoryRegionData((DWORD)PInputBuf->ProcessID, NULL, (PVOID)(UINT_PTR)(PInputBuf->StartAddress), &(POutputBuf->protection), &length, &BaseAddress);

				if (s_qvmDiag <= 5) {
					DbgPrint("[QVM-DIAG] Fallback: PID=%llu VA=0x%llX -> status=0x%X prot=0x%X len=0x%llX base=0x%llX\n",
						PInputBuf->ProcessID, PInputBuf->StartAddress,
						ntStatus, POutputBuf->protection, (UINT64)length, (UINT64)BaseAddress);
				}
			}
		}
		__except (1)
		{
			DbgPrint("GetMemoryRegionData error");
			ntStatus = STATUS_UNSUCCESSFUL;
			break;
		}

		POutputBuf->length = (UINT64)length;

		if (ShowResult)
		{
			DbgPrint("GetMemoryRegionData returned %x\n", ntStatus);
			DbgPrint("protection=%x\n", POutputBuf->protection);
			DbgPrint("length=%p\n", POutputBuf->length);
			DbgPrint("BaseAddress=%p\n", BaseAddress);
		}



		break;
	}


	case IOCTL_CE_TEST: //just a test to see it's working
	{
		UNICODE_STRING test;
		PVOID x;
		QWORD a, b;

		_disable();
		a = __rdtsc();
		b = __rdtsc();

		_enable();


		DbgPrint("%d\n", (int)(b - a));
		break;
	}

	case IOCTL_CE_GETPETHREAD:
	{

		*(PUINT64)Irp->AssociatedIrp.SystemBuffer = (UINT64)getPEThread((UINT_PTR) * (PULONG)Irp->AssociatedIrp.SystemBuffer);
		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_GETPEPROCESS:
	{
		DWORD processid = *(PDWORD)Irp->AssociatedIrp.SystemBuffer;
		PEPROCESS selectedprocess;


		if (processid == 0)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
		}
		else
		{
			if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(processid), &selectedprocess) == STATUS_SUCCESS)
			{
#ifdef AMD64
				* (PUINT64)Irp->AssociatedIrp.SystemBuffer = (UINT64)selectedprocess;
#else
				* (PUINT64)Irp->AssociatedIrp.SystemBuffer = (DWORD)selectedprocess;
#endif
				//DbgPrint("PEProcess=%llx\n", *(PUINT64)Irp->AssociatedIrp.SystemBuffer);
				ObDereferenceObject(selectedprocess);

			}
			else
				*(PUINT64)Irp->AssociatedIrp.SystemBuffer = 0;
		}



		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_READPHYSICALMEMORY:
	{
		struct input
		{
			UINT64 startaddress;
			UINT64 bytestoread;
		} *pinp;
		pinp = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("IOCTL_CE_READPHYSICALMEMORY:pinp->startaddress=%x, pinp->bytestoread=%d", pinp->startaddress, pinp->bytestoread);


		ntStatus = ReadPhysicalMemory((PVOID)(UINT_PTR)pinp->startaddress, (UINT_PTR)pinp->bytestoread, pinp);
		break;



	}

	case IOCTL_CE_WRITEPHYSICALMEMORY:
	{
		HANDLE			physmem;
		UNICODE_STRING	physmemString;
		OBJECT_ATTRIBUTES attributes;
		WCHAR			physmemName[] = L"\\device\\physicalmemory";
		UCHAR* memoryview;

		RtlInitUnicodeString(&physmemString, physmemName);

		InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);
		ntStatus = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes);
		if (ntStatus == STATUS_SUCCESS)
		{
			//hey look, it didn't kill it
			struct input
			{
				UINT64 startaddress;
				UINT64 bytestoread;
			} *pinp;

			UCHAR* pinp2;

			SIZE_T length;
			PHYSICAL_ADDRESS	viewBase;
			UINT_PTR offset;
			UINT_PTR toread;


			pinp = Irp->AssociatedIrp.SystemBuffer;
			pinp2 = (UCHAR*)pinp;
			viewBase.QuadPart = (ULONGLONG)(pinp->startaddress);

			length = 0x2000;//pinp->bytestoread;
			toread = (UINT_PTR)pinp->bytestoread;

			memoryview = NULL;
			ntStatus = ZwMapViewOfSection(
				physmem,  //sectionhandle
				NtCurrentProcess(), //processhandle
				&memoryview, //BaseAddress
				0L, //ZeroBits
				length, //CommitSize
				&viewBase, //SectionOffset
				&length, //ViewSize
				ViewShare,
				0,
				PAGE_READWRITE);

			if (ntStatus == STATUS_SUCCESS)
			{
				offset = (UINT_PTR)(pinp->startaddress) - (UINT_PTR)viewBase.QuadPart;
				RtlCopyMemory(&memoryview[offset], &pinp2[16], toread);

				ZwUnmapViewOfSection(
					NtCurrentProcess(), //processhandle
					memoryview);
			}

			ZwClose(physmem);
		}

		break;
	}



	case IOCTL_CE_GETPHYSICALADDRESS:
	{
		struct input
		{
			UINT64  ProcessID;
			UINT64 BaseAddress;
		} *pinp;

		PEPROCESS selectedprocess;
		PHYSICAL_ADDRESS physical;
		physical.QuadPart = 0;

		ntStatus = STATUS_SUCCESS;
		pinp = Irp->AssociatedIrp.SystemBuffer;

		//DbgPrint("IOCTL_CE_GETPHYSICALADDRESS. ProcessID(%p)=%x BaseAddress(%p)=%x\n",&pinp->ProcessID, pinp->ProcessID, &pinp->BaseAddress, pinp->BaseAddress);

		__try
		{
			if (SvmBridge_IsActive())
			{
				/* [StealthScan] 零 KeStackAttachProcess — 直接页表遍历 */
				physical.QuadPart = (LONGLONG)StealthGetPhysAddr(
					pinp->ProcessID, pinp->BaseAddress);
				ntStatus = (physical.QuadPart != 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			}
			else
			{
				if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(pinp->ProcessID), &selectedprocess) == STATUS_SUCCESS)
				{
					KAPC_STATE apc_state;
					RtlZeroMemory(&apc_state, sizeof(apc_state));
					KeStackAttachProcess((PVOID)selectedprocess, &apc_state);
					__try
					{
						physical = MmGetPhysicalAddress((PVOID)(UINT_PTR)pinp->BaseAddress);
					}
					__finally
					{
						KeUnstackDetachProcess(&apc_state);
					}
					ObDereferenceObject(selectedprocess);
				}
			}
		}
		__except (1)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		if (ntStatus == STATUS_SUCCESS)
		{
			//DbgPrint("physical.LowPart=%x",physical.LowPart);
			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &physical.QuadPart, 8);

		}


		break;
	}

	case IOCTL_CE_GETMEMORYRANGES:
	{

		struct output
		{
			UINT64 address;
			UINT64 size;
		} *poutp = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("IOCTL_CE_GETMEMORYRANGES\n");


		if (PhysicalMemoryRanges == 0)
		{
			__try
			{
				PPHYSICAL_MEMORY_RANGE mr = MmGetPhysicalMemoryRanges();

				if (mr)
				{
					//find the end
					int i;
					PhysicalMemoryRanges = (UINT64)mr;
					for (i = 0; mr[i].NumberOfBytes.QuadPart || mr[i].BaseAddress.QuadPart; i++);

					PhysicalMemoryRangesListSize = (UINT64)(&mr[i]) - (UINT64)(&mr[0]);
				}



			}
			__except (1)
			{
				//just in case this function decides to bug out in the future
			}
		}

		poutp->address = PhysicalMemoryRanges;
		poutp->size = PhysicalMemoryRangesListSize;

		ntStatus = STATUS_SUCCESS;

		break;
	}

	case IOCTL_CE_GETSDTADDRESS:
	{
		DbgPrint("Obsolete\n");
		ntStatus = STATUS_UNSUCCESSFUL;
		break;
	}


	case IOCTL_CE_GETCR0:
	{
		*(UINT64*)Irp->AssociatedIrp.SystemBuffer = getCR0();
		ntStatus = STATUS_SUCCESS;

		break;
	}


	case IOCTL_CE_GETCR4:
	{
		//seems CR4 isn't seen as a register...
		*(UINT64*)Irp->AssociatedIrp.SystemBuffer = (UINT64)getCR4();
		ntStatus = STATUS_SUCCESS;

		break;
	}


	case IOCTL_CE_SETCR4:
	{
		//seems CR4 isn't seen as a register...
		ULONG cr4reg = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
		setCR4((UINT64)cr4reg);
		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_GETCR3:
	{
		UINT_PTR cr3reg = 0;
		PEPROCESS selectedprocess;


		ntStatus = STATUS_SUCCESS;

		if (SvmBridge_IsActive())
		{
			/* [StealthScan] 零 KeStackAttachProcess — 直接读 EPROCESS+0x28 */
			cr3reg = (UINT_PTR)StealthGetProcessCr3(
				(UINT64)(*(ULONG*)Irp->AssociatedIrp.SystemBuffer));
		}
		else
		{
			if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(*(ULONG*)Irp->AssociatedIrp.SystemBuffer), &selectedprocess) == STATUS_SUCCESS)
			{
				__try
				{
					KAPC_STATE apc_state;
					RtlZeroMemory(&apc_state, sizeof(apc_state));
					KeStackAttachProcess((PVOID)selectedprocess, &apc_state);
					__try
					{
						cr3reg = (UINT_PTR)getCR3();
					}
					__finally
					{
						KeUnstackDetachProcess(&apc_state);
					}
				}
				__except (1)
				{
					ntStatus = STATUS_UNSUCCESSFUL;
					break;
				}
				ObDereferenceObject(selectedprocess);
			}
		}

		DbgPrint("cr3reg=%p\n", cr3reg);

		*(UINT64*)Irp->AssociatedIrp.SystemBuffer = cr3reg;

		break;
	}



	case IOCTL_CE_GETSDT:
	{
		//returns the address of KeServiceDescriptorTable
		ntStatus = STATUS_UNSUCCESSFUL;
		break;
	}



	case IOCTL_CE_GETIDT:
	{
		//returns the address of the IDT of the current CPU
		IDT idt;
		RtlZeroMemory(&idt, sizeof(IDT));
		GetIDT(&idt);
		RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, 2 + 8); //so that the 32-bit version doesn't have to deal with garbage at the end
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &idt, sizeof(IDT)); //copy idt
		ntStatus = STATUS_SUCCESS;

		break;
	}

	case IOCTL_CE_GETGDT:
	{
		//returns the address of the IDT of the current CPU
		GDT gdt;
		RtlZeroMemory(&gdt, sizeof(GDT));
		GetGDT(&gdt);
		RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, 2 + 8);
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &gdt, sizeof(GDT)); //copy gdt
		ntStatus = STATUS_SUCCESS;

		break;
	}

	case IOCTL_CE_LAUNCHDBVM:
	{
		/* [SVM-FIX] DBVM is an Intel VMX hypervisor. On AMD systems with SvmDebug,
		 * launching DBVM will: disable paging → switch CR3 → jump to 0x00400000
		 * → guaranteed triple-fault → instant BSOD/reboot.
		 * Block this IOCTL entirely when running on AMD+SVM. */
		if (SvmBridge_IsActive())
		{
			DbgPrint("[DBK-SVM] IOCTL_CE_LAUNCHDBVM BLOCKED: DBVM is Intel-only, SvmDebug provides equivalent functionality on AMD\n");
			ntStatus = STATUS_NOT_SUPPORTED;
			break;
		}

		{
			struct intput
			{
				UINT64 dbvmimgpath;
				DWORD32 cpuid;
			} *pinp;
			pinp = Irp->AssociatedIrp.SystemBuffer;
			DbgPrint("IOCTL_CE_LAUNCHDBVM\n");

			initializeDBVM((PCWSTR)(UINT_PTR)pinp->dbvmimgpath);

			if (pinp->cpuid == 0xffffffff) {
				forEachCpu(vmxoffload_dpc, NULL, NULL, NULL, vmxoffload_override);
				cleanupDBVM();
			}
			else
				forOneCpu((CCHAR)pinp->cpuid, vmxoffload_dpc, NULL, NULL, NULL, vmxoffload_override);

			DbgPrint("Returned from vmxoffload()\n");
		}
		break;
	}


	case IOCTL_CE_HOOKINTS: //hooks the DEBUG interrupts
	{
		DbgPrint("IOCTL_CE_HOOKINTS\n");
		forEachCpu(debugger_initHookForCurrentCPU_DPC, NULL, NULL, NULL, NULL);
		ntStatus = STATUS_SUCCESS;

		/*
		DbgPrint("IOCTL_CE_HOOKINTS for cpu %d\n", cpunr());
		if (debugger_initHookForCurrentCPU())
			ntStatus=STATUS_SUCCESS;
		else
			ntStatus=STATUS_UNSUCCESSFUL;*/

		break;
	}

	case IOCTL_CE_USERDEFINEDINTERRUPTHOOK:
	{
		struct intput
		{
			UINT64 interruptnumber;
			UINT64 newCS;
			UINT64 newRIP;
			UINT64 addressofjumpback;
		} *pinp;
		DbgPrint("IOCTL_CE_USERDEFINEDINTERRUPTHOOK\n");

		pinp = Irp->AssociatedIrp.SystemBuffer;


		inthook_HookInterrupt((unsigned char)(pinp->interruptnumber), (int)pinp->newCS, (ULONG_PTR)pinp->newRIP, (PJUMPBACK)(UINT_PTR)(pinp->addressofjumpback));
		DbgPrint("After the hook\n");
		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_UNHOOKALLINTERRUPTS:
	{
		int i;
		DbgPrint("IOCTL_CE_UNHOOKALLINTERRUPTS for cpu %d\n", cpunr());
		for (i = 0; i < 256; i++)
			inthook_UnhookInterrupt((unsigned char)i);

		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_SETGLOBALDEBUGSTATE:
	{
		struct intput
		{
			BOOL newstate;
		} *pinp;
		pinp = Irp->AssociatedIrp.SystemBuffer;

		debugger_setGlobalDebugState(pinp->newstate);
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_DEBUGPROCESS:
	{
		struct input
		{
			DWORD	ProcessID;
		} *pinp;

		DbgPrint("IOCTL_CE_DEBUGPROCESS\n");
		pinp = Irp->AssociatedIrp.SystemBuffer;
		debugger_startDebugging(pinp->ProcessID);

		ntStatus = STATUS_SUCCESS;

		break;

	}

	case IOCTL_CE_STOPDEBUGGING:
	{
		debugger_stopDebugging();
		ntStatus = STATUS_SUCCESS;
		break;
	}





	case IOCTL_CE_STARTPROCESSWATCH:
	{
		NTSTATUS r = STATUS_SUCCESS;
		DbgPrint("IOCTL_CE_STARTPROCESSWATCH\n");

		ProcessWatcherOpensHandles = *(char*)Irp->AssociatedIrp.SystemBuffer != 0;

		if (CreateProcessNotifyRoutineEnabled && WatcherProcess)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
			break;
		}

		//still here
		ExAcquireResourceExclusiveLite(&ProcesslistR, TRUE);
		ProcessEventCount = 0;
		ExReleaseResourceLite(&ProcesslistR);

		//DbgPrint("IOCTL_CE_STARTPROCESSWATCH\n");

		CleanProcessList();



		if ((r == STATUS_SUCCESS) && (CreateProcessNotifyRoutineEnabled == FALSE))
		{

			DbgPrint("calling PsSetCreateProcessNotifyRoutine\n");


#if (NTDDI_VERSION >= NTDDI_VISTASP1) 
			r = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, FALSE);
			CreateProcessNotifyRoutineEnabled = r == STATUS_SUCCESS;
#else
			CreateProcessNotifyRoutineEnabled = (PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE) == STATUS_SUCCESS);
#endif
			if (CreateProcessNotifyRoutineEnabled)
				CreateThreadNotifyRoutineEnabled = (PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine) == STATUS_SUCCESS);
		}

		ntStatus = (CreateProcessNotifyRoutineEnabled) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

		if (ntStatus == STATUS_SUCCESS)
			DbgPrint("CreateProcessNotifyRoutineEnabled worked\n");
		else
			DbgPrint("CreateProcessNotifyRoutineEnabled failed (r=%x)\n", r);


		break;
	}



	case IOCTL_CE_GETPROCESSEVENTS:
	{

		ExAcquireResourceExclusiveLite(&ProcesslistR, TRUE);

		*(PUCHAR)Irp->AssociatedIrp.SystemBuffer = ProcessEventCount;
		RtlCopyMemory((PVOID)((UINT_PTR)Irp->AssociatedIrp.SystemBuffer + 1), &ProcessEventdata[0], ProcessEventCount * sizeof(ProcessEventdta));
		ProcessEventCount = 0; //there's room for new events

		ExReleaseResourceLite(&ProcesslistR);

		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_GETTHREADEVENTS:
	{
		ExAcquireResourceExclusiveLite(&ProcesslistR, TRUE);

		*(PUCHAR)Irp->AssociatedIrp.SystemBuffer = ThreadEventCount;
		RtlCopyMemory((PVOID)((UINT_PTR)Irp->AssociatedIrp.SystemBuffer + 1), &ThreadEventData[0], ThreadEventCount * sizeof(ThreadEventDta));
		ThreadEventCount = 0; //there's room for new events

		ExReleaseResourceLite(&ProcesslistR);

		ntStatus = STATUS_SUCCESS;
		break;
	}



	case IOCTL_CE_CREATEAPC:
	{
		struct input
		{
			UINT64 threadid;
			UINT64 addresstoexecute;
		} *inp;
		inp = Irp->AssociatedIrp.SystemBuffer;

		CreateRemoteAPC((ULONG)inp->threadid, (PVOID)(UINT_PTR)inp->addresstoexecute);
		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_SUSPENDTHREAD:
	{
		struct input
		{
			ULONG threadid;
		} *inp;
		inp = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("CE_SUSPENDTHREAD\n");

		DBKSuspendThread(inp->threadid);
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_RESUMETHREAD:
	{
		struct input
		{
			ULONG threadid;
		} *inp;
		inp = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("CE_RESUMETHREAD\n");

		DBKResumeThread(inp->threadid);
		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_SUSPENDPROCESS:
	{
		struct input
		{
			ULONG processid;
		} *inp;
		inp = Irp->AssociatedIrp.SystemBuffer;



		DbgPrint("IOCTL_CE_SUSPENDPROCESS\n");

		if (PsSuspendProcess)
		{
			PEPROCESS selectedprocess;
			if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->processid), &selectedprocess) == STATUS_SUCCESS)
			{
				ntStatus = PsSuspendProcess(selectedprocess);
				ObDereferenceObject(selectedprocess);
			}
			else
				ntStatus = STATUS_NOT_FOUND;
		}
		else
			ntStatus = STATUS_NOT_IMPLEMENTED;

		break;
	}


	case IOCTL_CE_RESUMEPROCESS:
	{
		struct input
		{
			ULONG processid;
		} *inp;
		inp = Irp->AssociatedIrp.SystemBuffer;



		DbgPrint("IOCTL_CE_RESUMEPROCESS\n");

		if (PsResumeProcess)
		{
			PEPROCESS selectedprocess;
			if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->processid), &selectedprocess) == STATUS_SUCCESS)
			{
				ntStatus = PsResumeProcess(selectedprocess);
				ObDereferenceObject(selectedprocess);
			}
			else
				ntStatus = STATUS_NOT_FOUND;
		}
		else
			ntStatus = STATUS_NOT_IMPLEMENTED;

		break;
	}

	case IOCTL_CE_ALLOCATEMEM:
	{
		struct input
		{
			UINT64 ProcessID;
			UINT64 BaseAddress;
			UINT64 Size;
			UINT64 AllocationType;
			UINT64 Protect;
		} *inp;
		PEPROCESS selectedprocess;

		PVOID BaseAddress;
		SIZE_T RegionSize;


		inp = Irp->AssociatedIrp.SystemBuffer;
		BaseAddress = (PVOID)(UINT_PTR)inp->BaseAddress;
		RegionSize = (SIZE_T)(inp->Size);


		if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->ProcessID), &selectedprocess) == STATUS_SUCCESS)
		{
			__try
			{
				KAPC_STATE apc_state;
				RtlZeroMemory(&apc_state, sizeof(apc_state));
				KeAttachProcess((PVOID)selectedprocess); //local process is much more fun!!!!

				DbgPrint("Switched Process\n");
				__try
				{
					DbgPrint("Calling ZwAllocateVirtualMemory\n");
					DbgPrint("Before call: BaseAddress=%p\n", BaseAddress);
					DbgPrint("Before call: RegionSize=%x\n", RegionSize);

					ntStatus = ZwAllocateVirtualMemory((HANDLE)-1, &BaseAddress, 0, &RegionSize, (ULONG)inp->AllocationType, (ULONG)inp->Protect);

					if ((ntStatus == STATUS_SUCCESS) && (HiddenDriver))
					{
						//initialize the memory with crap so it becomes paged
						int i;
						char* x;
						x = BaseAddress;
						for (i = 0; i < (int)RegionSize; i++)
							x[i] = (unsigned char)i;
					}

					DbgPrint("ntStatus=%x\n", ntStatus);
					DbgPrint("BaseAddress=%p\n", BaseAddress);
					DbgPrint("RegionSize=%x\n", RegionSize);
					*(PUINT64)Irp->AssociatedIrp.SystemBuffer = 0;
					*(PUINT_PTR)Irp->AssociatedIrp.SystemBuffer = (UINT_PTR)BaseAddress;

				}
				__finally
				{
					KeDetachProcess();
				}

			}
			__except (1)
			{
				ntStatus = STATUS_UNSUCCESSFUL;
				break;
			}


			ObDereferenceObject(selectedprocess);
		}

		break;
	}


	case IOCTL_CE_ALLOCATEMEM_NONPAGED:
	{
		struct input
		{
			ULONG Size;
		} *inp;
		PVOID address;
		int size;

		inp = Irp->AssociatedIrp.SystemBuffer;
		size = inp->Size;

		address = ExAllocatePool(NonPagedPool, size);
		*(PUINT64)Irp->AssociatedIrp.SystemBuffer = 0;
		*(PUINT_PTR)Irp->AssociatedIrp.SystemBuffer = (UINT_PTR)address;


		if (address == 0)
			ntStatus = STATUS_UNSUCCESSFUL;
		else
		{
			DbgPrint("Alloc success. Cleaning memory... (size=%d)\n", size);

			DbgPrint("address=%p\n", address);
			RtlZeroMemory(address, size);

			ntStatus = STATUS_SUCCESS;
		}

		break;
	}

	case IOCTL_CE_FREE_NONPAGED:
	{
		struct input
		{
			UINT64 Address;
		} *inp;

		inp = Irp->AssociatedIrp.SystemBuffer;

		ExFreePool((PVOID)(UINT_PTR)inp->Address);

		ntStatus = STATUS_SUCCESS;

		break;
	}


	case IOCTL_CE_MAP_MEMORY:
	{
		struct input
		{
			UINT64 FromPID;
			UINT64 ToPID;
			UINT64 address;
			DWORD size;
		} *inp;

		struct output
		{
			UINT64 FromMDL;
			UINT64 Address;
		} *outp;

		KAPC_STATE apc_state;
		PEPROCESS selectedprocess;
		PMDL FromMDL = NULL;

		inp = Irp->AssociatedIrp.SystemBuffer;
		outp = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("IOCTL_CE_MAP_MEMORY\n");
		DbgPrint("address %x size %d\n", inp->address, inp->size);
		ntStatus = STATUS_UNSUCCESSFUL;

		if (inp->FromPID)
		{
			//switch
			DbgPrint("From PID %d\n", inp->FromPID);
			if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->FromPID), &selectedprocess) == STATUS_SUCCESS)
			{
				__try
				{
					RtlZeroMemory(&apc_state, sizeof(apc_state));
					KeStackAttachProcess((PVOID)selectedprocess, &apc_state);

					__try
					{
						FromMDL = IoAllocateMdl((PVOID)(UINT_PTR)inp->address, inp->size, FALSE, FALSE, NULL);
						if (FromMDL)
							MmProbeAndLockPages(FromMDL, KernelMode, IoReadAccess);
					}
					__finally
					{
						KeUnstackDetachProcess(&apc_state);
					}

				}
				__except (1)
				{
					DbgPrint("Exception\n");
					ntStatus = STATUS_UNSUCCESSFUL;
					break;
				}

				ObDereferenceObject(selectedprocess);
			}
		}
		else
		{
			DbgPrint("From kernel or self\n", inp->FromPID);
			__try
			{
				FromMDL = IoAllocateMdl((PVOID)(UINT_PTR)inp->address, inp->size, FALSE, FALSE, NULL);
				if (FromMDL)
				{
					DbgPrint("IoAllocateMdl success\n");
					MmProbeAndLockPages(FromMDL, KernelMode, IoReadAccess);
				}
			}
			__except (1)
			{
				DbgPrint("Exception\n");

				if (FromMDL)
				{
					IoFreeMdl(FromMDL);
					FromMDL = NULL;
				}
			}
		}

		if (FromMDL)
		{
			DbgPrint("FromMDL is valid\n");

			if (inp->ToPID)
			{
				//switch
				DbgPrint("To PID %d\n", inp->ToPID);
				if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->ToPID), &selectedprocess) == STATUS_SUCCESS)
				{
					__try
					{
						RtlZeroMemory(&apc_state, sizeof(apc_state));
						KeStackAttachProcess((PVOID)selectedprocess, &apc_state);

						__try
						{
							outp->Address = (UINT64)MmMapLockedPagesSpecifyCache(FromMDL, UserMode, MmWriteCombined, NULL, FALSE, NormalPagePriority);
							outp->FromMDL = (UINT64)FromMDL;
							ntStatus = STATUS_SUCCESS;
						}
						__finally
						{
							KeUnstackDetachProcess(&apc_state);
						}

					}
					__except (1)
					{
						DbgPrint("Exception part 2\n");
						ntStatus = STATUS_UNSUCCESSFUL;
						break;
					}

					ObDereferenceObject(selectedprocess);
				}
			}
			else
			{
				DbgPrint("To kernel or self\n", inp->FromPID);

				__try
				{
					outp->Address = (UINT64)MmMapLockedPagesSpecifyCache(FromMDL, UserMode, MmWriteCombined, NULL, FALSE, NormalPagePriority);
					outp->FromMDL = (UINT64)FromMDL;
					ntStatus = STATUS_SUCCESS;
				}
				__except (1)
				{
					DbgPrint("Exception part 2\n");
				}
			}





		}
		else
			DbgPrint("FromMDL==NULL\n");



		break;
	}

	case IOCTL_CE_UNMAP_MEMORY:
	{
		struct output
		{
			UINT64 FromMDL;
			UINT64 Address;
		} *inp;

		PMDL mdl;

		inp = Irp->AssociatedIrp.SystemBuffer;
		mdl = (PMDL)(UINT_PTR)inp->FromMDL;

		MmUnmapLockedPages((PMDL)(UINT_PTR)inp->Address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		ntStatus = STATUS_SUCCESS; //no BSOD means success ;)

		break;
	}

	case IOCTL_CE_LOCK_MEMORY:
	{
		struct
		{
			UINT64 ProcessID;
			UINT64 address;
			UINT64 size;
		} *inp;

		struct
		{
			UINT64 mdl;
		} *outp;
		KAPC_STATE apc_state;
		PEPROCESS selectedprocess;

		DbgPrint("IOCTL_CE_LOCK_MEMORY");
		inp = Irp->AssociatedIrp.SystemBuffer;
		outp = Irp->AssociatedIrp.SystemBuffer;



		if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->ProcessID), &selectedprocess) == STATUS_SUCCESS)
		{
			PMDL mdl = NULL;
			KeStackAttachProcess(selectedprocess, &apc_state);

			__try
			{
				mdl = IoAllocateMdl((PVOID)(UINT_PTR)inp->address, (ULONG)inp->size, FALSE, FALSE, NULL);
				if (mdl)
				{
					__try
					{
						MmProbeAndLockPages(mdl, UserMode, IoReadAccess);

						DbgPrint("MmProbeAndLockPages succeeded");
					}
					__except (1)
					{
						DbgPrint("MmProbeAndLockPages failed");
						IoFreeMdl(mdl);
						ntStatus = STATUS_UNSUCCESSFUL;
						break;
					}

				}
			}
			__finally
			{
				KeUnstackDetachProcess(&apc_state);
			}

			outp->mdl = (UINT_PTR)mdl;


			DbgPrint("Locked the page\n");
			ntStatus = STATUS_SUCCESS;
		}

		break;
	}

	case IOCTL_CE_UNLOCK_MEMORY:
	{
		struct
		{
			UINT64 mdl;
		} *inp;
		DbgPrint("IOCTL_CE_UNLOCK_MEMORY");
		inp = Irp->AssociatedIrp.SystemBuffer;

		MmUnlockPages((PMDL)(UINT_PTR)inp->mdl);
		IoFreeMdl((PMDL)(UINT_PTR)inp->mdl);
		break;
	}

	case IOCTL_CE_GETPROCADDRESS:
	{
		struct input
		{
			UINT64 s;
		} *inp;
		UNICODE_STRING y;
		UINT64 result;
		PVOID x;



		inp = Irp->AssociatedIrp.SystemBuffer;

		RtlInitUnicodeString(&y, (PCWSTR)(UINT_PTR)(inp->s));
		x = MmGetSystemRoutineAddress(&y);
		result = (UINT64)x;


		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &result, 8);
		ntStatus = STATUS_SUCCESS;

		break;
	}

	case IOCTL_CE_GETPROCESSNAMEADDRESS:
	{
		struct input
		{
			UINT64 PEPROCESS;
		} *inp;

		struct output
		{
			UINT64 Address;
		} *outp;

		UNICODE_STRING temp;

		inp = Irp->AssociatedIrp.SystemBuffer;
		outp = Irp->AssociatedIrp.SystemBuffer;

		RtlInitUnicodeString(&temp, L"PsGetProcessImageFileName");
		PsGetProcessImageFileName = (GET_PROCESS_IMAGE_NAME)MmGetSystemRoutineAddress(&temp);
		if (PsGetProcessImageFileName != NULL)
		{
			outp->Address = (UINT_PTR)PsGetProcessImageFileName((PEPROCESS)((UINT_PTR)(inp->PEPROCESS)));
			ntStatus = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("PsGetProcessImageFileName==NULL");
			ntStatus = STATUS_UNSUCCESSFUL;
		}


		break;
	}
	/*x
			case IOCTL_CE_MAKEKERNELCOPY:
				{
					struct input
					{
						ULONG Base;
						ULONG KernelSize;
					} *inp;
					DbgPrint("IOCTL_CE_MAKEKERNELCOPY");
					inp=Irp->AssociatedIrp.SystemBuffer;
					ntStatus=makeKernelCopy(inp->Base, inp->KernelSize);
					break;
				}
	*/


	case IOCTL_CE_CONTINUEDEBUGEVENT:
	{
		struct input
		{
			BOOL handled;
		} *inp = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("IOCTL_CE_CONTINUEDEBUGEVENT\n");
		ntStatus = debugger_continueDebugEvent(inp->handled);
		break;

	}

	case IOCTL_CE_WAITFORDEBUGEVENT:
	{
		struct input
		{
			ULONG timeout;
		} *inp = Irp->AssociatedIrp.SystemBuffer;

		ntStatus = debugger_waitForDebugEvent(inp->timeout);

		break;

	}

	case IOCTL_CE_GETDEBUGGERSTATE:
	{
		DbgPrint("IOCTL_CE_GETDEBUGGERSTATE\n");
		__try
		{
			ntStatus = debugger_getDebuggerState((PDebugStackState)(Irp->AssociatedIrp.SystemBuffer));
		}
		__except (1)
		{
			DbgPrint("Exception happened\n");
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		DbgPrint("ntStatus=%x rax=%x\n", ntStatus, ((PDebugStackState)(Irp->AssociatedIrp.SystemBuffer))->rax);
		break;
	}

	case IOCTL_CE_SETDEBUGGERSTATE:
	{
		DbgPrint("IOCTL_CE_SETDEBUGGERSTATE: state->rax=%x\n", ((PDebugStackState)(Irp->AssociatedIrp.SystemBuffer))->rax);
		__try
		{
			ntStatus = debugger_setDebuggerState((PDebugStackState)Irp->AssociatedIrp.SystemBuffer);
		}
		__except (1)
		{
			DbgPrint("Exception happened\n");
			ntStatus = STATUS_UNSUCCESSFUL;
		}
		break;
	}

	case IOCTL_CE_SETKERNELSTEPABILITY:
	{
		struct input
		{
			int state;

		} *inp = Irp->AssociatedIrp.SystemBuffer;
		KernelCodeStepping = inp->state;
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_WRITESIGNOREWP:
	{
		KernelWritesIgnoreWP = *(BYTE*)Irp->AssociatedIrp.SystemBuffer;
		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_GD_SETBREAKPOINT:
	{
		struct input
		{
			BOOL active;
			int debugregspot;
			UINT64 address;
			DWORD breakType;
			DWORD breakLength;
		} *inp = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("sizeof(struct input)=%d\n", sizeof(struct input));
		//DbgPrint("address=%llx breakType=%d breakLength=%d\n",inp->address, inp->breakType,inp->breakLength);

		if (inp->active)
		{
			DbgPrint("activating breapoint %d\n", inp->debugregspot);
			ntStatus = debugger_setGDBreakpoint(inp->debugregspot, (UINT_PTR)inp->address, (BreakType)inp->breakType, (BreakLength)inp->breakLength);
		}
		else
		{
			DbgPrint("Deactivating breakpoint :%d\n", inp->debugregspot);
			ntStatus = debugger_unsetGDBreakpoint(inp->debugregspot);
		}
		break;
	}

	case IOCTL_CE_TOUCHDEBUGREGISTER: //used after setting a global debug breakpoint
	{
		debugger_touchDebugRegister(0);
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_SETSTORELBR:
	{
		BOOL newstate = *(PBOOL)Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("Calling debugger_setStoreLBR(%d)\n", newstate);
		debugger_setStoreLBR(newstate);
		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_EXECUTE_CODE:
	{
		typedef NTSTATUS(*PARAMETERLESSFUNCTION)(UINT64 parameters);
		PARAMETERLESSFUNCTION functiontocall;

		struct input
		{
			UINT64	functionaddress; //function address to call
			UINT64	parameters;
		} *inp = Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("IOCTL_CE_EXECUTE_CODE\n");

		functiontocall = (PARAMETERLESSFUNCTION)(UINT_PTR)(inp->functionaddress);

		__try
		{
			ntStatus = functiontocall(inp->parameters);
			DbgPrint("Still alive\n");
			ntStatus = STATUS_SUCCESS;
		}
		__except (1)
		{
			DbgPrint("Exception occured\n");
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		break;
	}


	case IOCTL_CE_GETVERSION:
	{
		DbgPrint("IOCTL_CE_GETVERSION. Version=%d\n", dbkversion);
		*(PULONG)Irp->AssociatedIrp.SystemBuffer = dbkversion;
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_READMSR:
	{
		DWORD msr = *(PDWORD)Irp->AssociatedIrp.SystemBuffer;

		//DbgPrint("IOCTL_CE_READMSR: msr=%x\n", msr);

		__try
		{
			*(PUINT64)Irp->AssociatedIrp.SystemBuffer = __readmsr(msr);
			//DbgPrint("Output: %llx\n",*(PUINT64)Irp->AssociatedIrp.SystemBuffer); 

			ntStatus = STATUS_SUCCESS;
		}
		__except (1)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		break;
	}

	case IOCTL_CE_WRITEMSR:
	{
		struct input
		{
			UINT64 msr;
			UINT64 value;
		} *inp = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("IOCTL_CE_WRITEMSR:\n");
		DbgPrint("msr=%llx\n", inp->msr);
		DbgPrint("value=%llx\n", inp->value);

		__try
		{
			__writemsr(inp->msr, inp->value);
			ntStatus = STATUS_SUCCESS;
		}
		__except (1)
		{
			DbgPrint("Error while writing value\n");
			ntStatus = STATUS_UNSUCCESSFUL;
		}
		break;
	}

	case IOCTL_CE_ULTIMAP2:
	{
		struct input
		{
			UINT32 PID;
			UINT32 Size;
			UINT32 RangeCount;
			UINT32 NoPMI;
			UINT32 UserMode;
			UINT32 KernelMode;
			URANGE Ranges[8];
			WCHAR OutputPath[200];
		} *inp = Irp->AssociatedIrp.SystemBuffer;
		int i;

		DbgPrint("IOCTL_CE_ULTIMAP2");
		for (i = 0; i < (int)(inp->RangeCount); i++)
			DbgPrint("%d=%p -> %p", i, (PVOID)(UINT_PTR)inp->Ranges[i].StartAddress, (PVOID)(UINT_PTR)inp->Ranges[i].EndAddress);

		SetupUltimap2(inp->PID, inp->Size, inp->OutputPath, inp->RangeCount, inp->Ranges, inp->NoPMI, inp->UserMode, inp->KernelMode);

		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_ULTIMAP2_WAITFORDATA:
	{

		ULONG timeout = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
		PULTIMAP2DATAEVENT output = Irp->AssociatedIrp.SystemBuffer;
		output->Address = 0;

		ntStatus = ultimap2_waitForData(timeout, output);

		break;
	}

	case IOCTL_CE_ULTIMAP2_LOCKFILE:
	{
		int cpunr = *(int*)Irp->AssociatedIrp.SystemBuffer;
		ultimap2_LockFile(cpunr);

		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_ULTIMAP2_RELEASEFILE:
	{
		int cpunr = *(int*)Irp->AssociatedIrp.SystemBuffer;
		ultimap2_ReleaseFile(cpunr);

		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_ULTIMAP2_GETTRACESIZE:
	{
		*(UINT64*)Irp->AssociatedIrp.SystemBuffer = ultimap2_GetTraceFileSize();
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_ULTIMAP2_RESETTRACESIZE:
	{
		ultimap2_ResetTraceFileSize();
		ntStatus = STATUS_SUCCESS;
		break;
	}


	case IOCTL_CE_ULTIMAP2_CONTINUE:
	{
		int cpunr = *(int*)Irp->AssociatedIrp.SystemBuffer;
		ntStatus = ultimap2_continue(cpunr);

		break;
	}

	case IOCTL_CE_ULTIMAP2_FLUSH:
	{
		ntStatus = ultimap2_flushBuffers();
		break;
	}

	case IOCTL_CE_ULTIMAP2_PAUSE:
	{
		ntStatus = ultimap2_pause();
		break;
	}

	case IOCTL_CE_ULTIMAP2_RESUME:
	{
		ntStatus = ultimap2_resume();
		break;
	}

	case IOCTL_CE_DISABLEULTIMAP2:
	{
		DisableUltimap2();
		break;
	}

	case IOCTL_CE_ULTIMAP:
	{
#pragma pack(1)
		struct input
		{
			UINT64 targetCR3;
			UINT64 dbgctl;
			UINT64 dsareasize;
			BOOL savetofile;
			int HandlerCount;
			WCHAR filename[200];
		} *inp = Irp->AssociatedIrp.SystemBuffer;
#pragma pack()


		DbgPrint("IOCTL_CE_ULTIMAP:\n");
		DbgPrint("ultimap(%I64x, %I64x, %d):\n", (UINT64)inp->targetCR3, (UINT64)inp->dbgctl, inp->dsareasize);

		if (inp->savetofile)
			DbgPrint("filename=%S\n", &inp->filename[0]);

		ntStatus = ultimap(inp->targetCR3, inp->dbgctl, (int)inp->dsareasize, inp->savetofile, &inp->filename[0], inp->HandlerCount);



		break;
	}

	case IOCTL_CE_ULTIMAP_DISABLE:
	{
		ultimap_disable();
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_ULTIMAP_WAITFORDATA:
	{

		ULONG timeout = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
		PULTIMAPDATAEVENT output = Irp->AssociatedIrp.SystemBuffer;
		ntStatus = ultimap_waitForData(timeout, output);

		break;
	}

	case IOCTL_CE_ULTIMAP_CONTINUE:
	{
		PULTIMAPDATAEVENT input = Irp->AssociatedIrp.SystemBuffer;
		ntStatus = ultimap_continue(input);

		break;
	}

	case IOCTL_CE_ULTIMAP_FLUSH:
	{
		ultimap_flushBuffers();
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_ULTIMAP_PAUSE:
	{
		ultimap_pause();
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_ULTIMAP_RESUME:
	{
		ultimap_resume();
		ntStatus = STATUS_SUCCESS;
		break;
	}

	/*
case IOCTL_CE_GETCPUIDS:
	{
		CPULISTFILLSTRUCT x;

		forEachCpuPassive(GetCPUIDS_all,&x);
	}*/

	case IOCTL_CE_STARTACCESMONITOR:
	{
		//this is used instead of writeProcessMemory for speed reasons (the reading out is still done with readProcessMemory because of easier memory management)
		struct input
		{
			UINT64 ProcessID;
		} *inp;
		PEPROCESS selectedprocess;

		PVOID BaseAddress;
		SIZE_T RegionSize;

		inp = Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("IOCTL_CE_STARTACCESMONITOR(%d)\n", inp->ProcessID);


		ntStatus = STATUS_UNSUCCESSFUL;

		if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->ProcessID), &selectedprocess) == STATUS_SUCCESS)
		{
			ntStatus = markAllPagesAsNeverAccessed(selectedprocess);
			ObDereferenceObject(selectedprocess);
		}

		break;
	}

	case IOCTL_CE_ENUMACCESSEDMEMORY:
	{
		struct input
		{
			UINT64 ProcessID;
		} *inp;
		PEPROCESS selectedprocess;

		PVOID BaseAddress;
		SIZE_T RegionSize;

		inp = Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("IOCTL_CE_ENUMACCESSEDMEMORY(%d)\n", inp->ProcessID);


		ntStatus = STATUS_UNSUCCESSFUL;

		if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->ProcessID), &selectedprocess) == STATUS_SUCCESS)
		{
			*(int*)Irp->AssociatedIrp.SystemBuffer = enumAllAccessedPages(selectedprocess);
			ObDereferenceObject(selectedprocess);
		}

		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_GETACCESSEDMEMORYLIST:
	{
		int ListSizeInBytes = *(int*)Irp->AssociatedIrp.SystemBuffer;
		PPRANGE List = (PPRANGE)Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("IOCTL_CE_GETACCESSEDMEMORYLIST\n");

		getAccessedPageList(List, ListSizeInBytes);

		DbgPrint("return from IOCTL_CE_GETACCESSEDMEMORYLIST\n");
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_CE_INITIALIZE:
	{
		//find the KeServiceDescriptorTableShadow 
		struct input
		{
			UINT64 AddressOfWin32K;
			UINT64 SizeOfWin32K;
			UINT64 NtUserBuildHwndList_callnumber;
			UINT64 NtUserQueryWindow_callnumber;
			UINT64 NtUserFindWindowEx_callnumber;
			UINT64 NtUserGetForegroundWindow_callnumber;
			UINT64 ActiveLinkOffset;
			UINT64 ProcessNameOffset;
			UINT64 DebugportOffset;
			UINT64 ProcessEvent;
			UINT64 ThreadEvent;
		} *pinp;

		DbgPrint("IOCTL_CE_INITIALIZE\n");
		pinp = Irp->AssociatedIrp.SystemBuffer;
		ntStatus = STATUS_SUCCESS;

		//referencing event handles to objects

		ObReferenceObjectByHandle((HANDLE)(UINT_PTR)pinp->ProcessEvent, EVENT_ALL_ACCESS, NULL, KernelMode, &ProcessEvent, NULL);
		ObReferenceObjectByHandle((HANDLE)(UINT_PTR)pinp->ThreadEvent, EVENT_ALL_ACCESS, NULL, KernelMode, &ThreadEvent, NULL);

		*(UINT_PTR*)Irp->AssociatedIrp.SystemBuffer = (UINT_PTR)0;
		break;
	}


	case IOCTL_CE_VMXCONFIG:
	{
#pragma pack(1)
		struct input
		{
			ULONG Virtualization_Enabled;
			QWORD Password1;
			ULONG Password2;
			QWORD Password3;
		} *pinp;
#pragma pack()


		DbgPrint("IOCTL_CE_VMXCONFIG called\n");
		ntStatus = STATUS_SUCCESS;

		pinp = Irp->AssociatedIrp.SystemBuffer;

		/* [SVM-FIX] When SvmDebug is active, vmx_getversion() executes vmmcall
		 * with DBVM password registers. SvmDebug's VMM does not understand the
		 * DBVM password protocol — the vmmcall may be mishandled.
		 * Skip the DBVM check entirely; SvmDebug provides all needed features. */
		if (SvmBridge_IsActive())
		{
			DbgPrint("[DBK-SVM] VMXCONFIG: SvmDebug active, skipping DBVM vmmcall probe\n");
			vmxusable = 0;  /* DBVM is not running — SvmDebug is the hypervisor */
			break;
		}

		if (pinp->Virtualization_Enabled)
		{
			vmx_password1 = pinp->Password1;
			vmx_password2 = pinp->Password2;
			vmx_password3 = pinp->Password3;

			DbgPrint("new passwords are: %p-%x-%p\n", (void*)vmx_password1, vmx_password2, (void*)vmx_password3);

			__try
			{
				vmx_version = vmx_getversion();
				DbgPrint("Still here, so vmx is loaded. vmx_version=%x\n", vmx_version);
				vmxusable = 1;
			}
			__except (1)
			{
				DbgPrint("Exception happened. This means no vmx installed, or one of the passwords is wrong\n");
				ntStatus = STATUS_UNSUCCESSFUL;

				vmxusable = 0;
			};
		}
		else
		{
			DbgPrint("Virtualization_Enabled=0\n");
			vmxusable = 0;
		}

		break;
	}


	case IOCTL_CE_ENABLE_DRM:
	{
#if (NTDDI_VERSION >= NTDDI_VISTA)				
		struct
		{
			QWORD PreferedAltitude;
			QWORD ProtectedProcess;
		} *inp = Irp->AssociatedIrp.SystemBuffer;



		DbgPrint("inp->PreferedAltitude=%p", inp->PreferedAltitude);
		DbgPrint("inp->PreferedAltitude=%p", inp->ProtectedProcess);


		if (DRMProcess)
		{
			//check if this process has been terminated
			LARGE_INTEGER timeout;

			timeout.QuadPart = -500000;
			ntStatus = KeWaitForSingleObject(DRMProcess, UserRequest, UserMode, FALSE, &timeout);

			if (ntStatus != STATUS_SUCCESS)
				break;
		}

		DRMProcess = PsGetCurrentProcess();

		if (inp->ProtectedProcess)
		{
			if (DRMProcess != (PEPROCESS)((UINT_PTR)inp->ProtectedProcess))
				DRMProcess2 = (PEPROCESS)((UINT_PTR)inp->ProtectedProcess);
		}

		DbgPrint("DRMProcess=%p", DRMProcess);
		DbgPrint("DRMProcess2=%p", DRMProcess2);

		if (DRMHandle == NULL)
		{
			WCHAR wcAltitude[10];
			UNICODE_STRING usAltitude;
			OB_CALLBACK_REGISTRATION r;
			LARGE_INTEGER tc;
			OB_OPERATION_REGISTRATION obr[2];
			int RandomVal = (int)(inp->PreferedAltitude);
			int trycount = 0;

			if (RandomVal == 0)
			{
				tc.QuadPart = 0;
				KeQueryTickCount(&tc);
				RandomVal = 1000 + (tc.QuadPart % 50000);
			}

			DbgPrint("Activating CE's super advanced DRM"); //yeah right....

			DbgPrint("RandomVal=%d", RandomVal);
			RtlStringCbPrintfW(wcAltitude, sizeof(wcAltitude) - 2, L"%d", RandomVal);

			DbgPrint("wcAltitude=%S", wcAltitude);
			RtlInitUnicodeString(&usAltitude, wcAltitude);

			r.Version = OB_FLT_REGISTRATION_VERSION;
			r.Altitude = usAltitude;
			r.RegistrationContext = NULL;


			obr[0].ObjectType = PsProcessType;
			obr[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
			obr[0].PreOperation = ProcessPreCallback;
			obr[0].PostOperation = ProcessPostCallback;

			obr[1].ObjectType = PsThreadType;
			obr[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
			obr[1].PreOperation = ThreadPreCallback;
			obr[1].PostOperation = ThreadPostCallback;

			r.OperationRegistration = obr;
			r.OperationRegistrationCount = 2;

			ntStatus = ObRegisterCallbacks(&r, &DRMHandle);

			while ((ntStatus == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) && (trycount < 10))
			{
				RandomVal++;
				RtlStringCbPrintfW(wcAltitude, sizeof(wcAltitude) - 2, L"%d", RandomVal);
				RtlInitUnicodeString(&usAltitude, wcAltitude);
				r.Altitude = usAltitude;

				trycount++;

				ntStatus = ObRegisterCallbacks(&r, &DRMHandle);
			}

			DbgPrint("ntStatus=%X", ntStatus);
		}
		else
			ntStatus = STATUS_SUCCESS;
#else
		ntStatus = STATUS_NOT_IMPLEMENTED;
#endif				
		break;
	}

	case IOCTL_CE_GET_PEB:
	{
		PEPROCESS ep = *(PEPROCESS*)Irp->AssociatedIrp.SystemBuffer;

		if (SvmBridge_IsActive())
		{
			/* [StealthScan] 零 KeStackAttachProcess — PsGetProcessPeb 直接返回 */
			PVOID peb = PsGetProcessPeb(ep);
			*(QWORD*)Irp->AssociatedIrp.SystemBuffer = (QWORD)peb;
			ntStatus = (peb != NULL) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		}
		else
		{
			KAPC_STATE oldstate;
			KeStackAttachProcess((PKPROCESS)ep, &oldstate);
			__try
			{
				ULONG r;
				PROCESS_BASIC_INFORMATION pbi;
				ntStatus = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &r);
				if (ntStatus == STATUS_SUCCESS)
					*(QWORD*)Irp->AssociatedIrp.SystemBuffer = (QWORD)(pbi.PebBaseAddress);
			}
			__finally
			{
				KeUnstackDetachProcess(&oldstate);
			}
		}

		break;
	}

	case IOCTL_CE_QUERYINFORMATIONPROCESS:
	{
		struct
		{
			QWORD processid;
			QWORD ProcessInformationAddress;
			QWORD ProcessInformationClass;
			QWORD ProcessInformationLength;
		}  *inp = Irp->AssociatedIrp.SystemBuffer;

		struct
		{
			QWORD result;
			QWORD returnLength;
			char data;
		} *outp = Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS selectedprocess;
		DbgPrint("IOCTL_CE_QUERYINFORMATIONPROCESS");

		if (inp->processid == 0)
		{
			DbgPrint("Still works\n");
			ntStatus = STATUS_SUCCESS;
			break;
		}
		__try
		{

			if (PsLookupProcessByProcessId((HANDLE)(UINT_PTR)inp->processid, &selectedprocess) == STATUS_SUCCESS)
			{
				KAPC_STATE oldstate;
				KeStackAttachProcess((PKPROCESS)selectedprocess, &oldstate);
				__try
				{
					ULONG returnLength;

					if (inp->ProcessInformationAddress == 0)
					{
						DbgPrint("NULL ProcessInformationAddress");
						outp->result = ZwQueryInformationProcess(NtCurrentProcess(), inp->ProcessInformationClass, NULL, (ULONG)inp->ProcessInformationLength, &returnLength);
					}
					else
						outp->result = ZwQueryInformationProcess(NtCurrentProcess(), inp->ProcessInformationClass, &(outp->data), (ULONG)inp->ProcessInformationLength, &returnLength);

					DbgPrint("outp->result=%x", outp->result);

					outp->returnLength = returnLength;
					DbgPrint("outp->returnLength=%x", outp->returnLength);

					ntStatus = STATUS_SUCCESS;
				}
				__finally
				{
					KeUnstackDetachProcess(&oldstate);
				}

				ObDereferenceObject(selectedprocess);
			}
			else
			{
				DbgPrint("Failed to find pid %x", inp->processid);
				ntStatus = STATUS_EXPIRED_HANDLE;
			}
		}
		__except (1)
		{
			DbgPrint("Exception");
			ntStatus = STATUS_EXPIRED_HANDLE;
		}
		break;
	}

	case IOCTL_CE_NTPROTECTVIRTUALMEMORY:
	{


		break;
	}

	case IOCTL_CE_ALLOCATE_MEMORY_FOR_DBVM:
	{
		PHYSICAL_ADDRESS LowAddress, HighAddress, SkipBytes;
		PMDL mdl;
		QWORD pagecount = *(QWORD*)Irp->AssociatedIrp.SystemBuffer;
		PFN_NUMBER* pfnlist;
		DbgPrint("IOCTL_CE_ALLOCATE_MEMORY_FOR_DBVM(%d)\n", pagecount);

		if (!vmxusable)
		{
			DbgPrint("This only works when DBVM is present\n");
			ntStatus = STATUS_INVALID_DEVICE_STATE;
			break;
		}

		LowAddress.QuadPart = 0;
		HighAddress.QuadPart = 0xffffffffffffffffI64;
		SkipBytes.QuadPart = 0;
		mdl = MmAllocatePagesForMdlEx(LowAddress, HighAddress, SkipBytes, (SIZE_T)pagecount * 4096, MmCached, MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS | MM_ALLOCATE_FULLY_REQUIRED); //do not free this, EVER
		if (mdl)
		{
			int i;
			PDBVMOffloadMemInfo mi;

			pagecount = MmGetMdlByteCount(mdl) / 4096;
			DbgPrint("Allocated %d pages\n", pagecount);

			pfnlist = MmGetMdlPfnArray(mdl);

			if (pfnlist)
			{
				//convert the pfnlist to a list dbvm understands, and go in blocks of 32
				mi = ExAllocatePool(PagedPool, sizeof(DBVMOffloadMemInfo));
				if (mi)
				{
					mi->List = ExAllocatePool(PagedPool, sizeof(UINT64) * 32);
					if (mi->List)
					{
						mi->Count = 0;
						for (i = 0; i < pagecount; i++)
						{
							mi->List[mi->Count] = pfnlist[i] << 12;
							mi->Count++;

							if (mi->Count == 32)
							{
								int j;
								int r = vmx_add_memory(mi->List, mi->Count);


								DbgPrint("vmx_add_memory for %d pages returned %d\n", mi->Count, r);

								for (j = 0; j < mi->Count; j++)
								{
									DbgPrint("%d : %p\n", j, (void*)((UINT_PTR)mi->List[j]));
								}


								mi->Count = 0;
							}
						}

						if (mi->Count)
						{
							int r = vmx_add_memory(mi->List, mi->Count);
							DbgPrint("vmx_add_memory for %d pages returned %d\n", mi->Count, r);
						}
						ExFreePool(mi->List);
					}
					else
						DbgPrint("Failure allocating mi->List");
					ExFreePool(mi);
				}
				else
					DbgPrint("Failure allocting mi");

			}
			else
				DbgPrint("Failure getting pfn list");
			ExFreePool(mdl); //only free the mdl, the rest belongs to dbvm now

			ntStatus = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("Failure allocating MDL");
			ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
		}


		break;
	}

	case IOCTL_CE_BATCH_READ:
	{
		ntStatus = HvBatchRead_Dispatch(
			Irp->AssociatedIrp.SystemBuffer,
			irpStack->Parameters.DeviceIoControl.InputBufferLength,
			irpStack->Parameters.DeviceIoControl.OutputBufferLength,
			&Irp->IoStatus.Information);
		break;
	}

	default:
		/* [NEW] Try SvmBridge dispatch first (handles 0x900 range IOCTLs) */
		if (SvmBridge_IsActive() && irpStack)
		{
			PVOID buf = Irp->AssociatedIrp.SystemBuffer;
			ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
			ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
			ULONG_PTR info = 0;
			NTSTATUS svmStatus = SvmBridge_DispatchIoctl(
				IoControlCode, buf, inLen, buf, outLen, &info);
			if (svmStatus != STATUS_INVALID_DEVICE_REQUEST)
			{
				/* SvmBridge handled it */
				ntStatus = svmStatus;
				Irp->IoStatus.Information = info;
				Irp->IoStatus.Status = ntStatus;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return ntStatus;
			}
		}
		DbgPrint("Unhandled IO request: %x\n", IoControlCode);
		break;
	}


	Irp->IoStatus.Status = ntStatus;

	// Set # of bytes to copy back to user-mode...
	if (irpStack) //only NULL when loaded by dbvm
	{
		if (ntStatus == STATUS_SUCCESS)
			Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		else
			Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}


	return ntStatus;
}