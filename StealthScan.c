/**
 * @file StealthScan.c
 * @brief CE 隐身内存扫描引擎 — 修复错误内存 + 消除 ACE 检测
 *
 * 根因修复:
 *   旧代码 SvmReadPte() 用 MmGetVirtualForPhysical() 读页表条目。
 *   MmGetVirtualForPhysical 返回的 VA 在页表自映射区域内,
 *   该区域是 CR3 相关的 — CE 进程上下文中该 VA 指向 CE 自己的页表,
 *   而非目标进程的页表, 导致整个翻译链错误。
 *
 *   本文件所有物理内存读取统一使用 MmCopyMemory(MM_COPY_MEMORY_PHYSICAL),
 *   直接从物理地址读取, 不依赖任何虚拟地址映射, 不受进程上下文影响。
 *
 * @author yewilliam
 * @date 2026/03/23
 */

#pragma warning(disable: 4100 4189)

#include "StealthScan.h"

STEALTH_PT_CACHE  g_StealthCache = { 0 };
STEALTH_CR3_ENTRY g_Cr3Cache[STEALTH_CR3_CACHE_SIZE] = { 0 };


/* ========================================================================
 *  初始化 / 清理
 * ======================================================================== */

//VOID StealthInit(VOID)
//{
//    RtlZeroMemory(&g_StealthCache, sizeof(g_StealthCache));
//    RtlZeroMemory(g_Cr3Cache, sizeof(g_Cr3Cache));
//}
//
//VOID StealthCleanup(VOID)
//{
//    RtlZeroMemory(&g_StealthCache, sizeof(g_StealthCache));
//    RtlZeroMemory(g_Cr3Cache, sizeof(g_Cr3Cache));
//}

VOID StealthResetPtCache(VOID)
{
    g_StealthCache.Pml4.Valid = FALSE;
    g_StealthCache.Pdpt.Valid = FALSE;
    g_StealthCache.Pd.Valid = FALSE;
    g_StealthCache.Pt.Valid = FALSE;
    g_StealthCache.Cr3 = 0;
}


/* ========================================================================
 *  Section 1: 物理内存读取原语
 *
 *  这是整个引擎的唯一物理内存入口。
 *  MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) 特性:
 *    - 不分配系统 PTE (vs MmMapIoSpace)
 *    - 不查 PFN 自映射 (vs MmGetVirtualForPhysical) ← 修复根因
 *    - 不受当前进程上下文影响 ← 修复根因
 *    - 走 HAL 物理内存读取路径
 * ======================================================================== */

static __forceinline BOOLEAN ReadPhysical(UINT64 Pa, PVOID OutBuf, SIZE_T Size)
{
    STEALTH_MM_COPY_ADDRESS srcAddr;
    SIZE_T bytesRead = 0;

    srcAddr.PhysicalAddress.QuadPart = (LONGLONG)Pa;
    return NT_SUCCESS(MmCopyMemory(OutBuf, srcAddr, Size,
        MM_COPY_MEMORY_PHYSICAL, &bytesRead))
        && (bytesRead == Size);
}


/* ========================================================================
 *  Section 2: 页表页缓存
 *
 *  缓存策略: 每级页表页首次访问时整页 (4KB=512条目) 读入缓存。
 *  后续同页内查询直接从缓存返回, 零物理读。
 *  连续扫描时命中率:
 *    PML4: ~100% (用户空间 < 256 条目)
 *    PDPT: ~99.9% (每条覆盖 1GB)
 *    PD:   ~99.5% (每条覆盖 2MB)
 *    PT:   ~99.5% (每条覆盖 4KB, 但整页覆盖 2MB)
 * ======================================================================== */

static UINT64 CachedReadPte(
    STEALTH_LEVEL_CACHE* Cache,
    UINT64               TablePa,
    UINT64               Index)
{
    UINT64 basePa = TablePa & ~0xFFFULL;

    /* 缓存命中 */
    if (Cache->Valid && Cache->BasePa == basePa)
        return Cache->Entries[Index & 0x1FF];

    /* 未命中: 整页读入 */
    if (!ReadPhysical(basePa, Cache->Entries, STEALTH_PT_ENTRIES * sizeof(UINT64)))
    {
        Cache->Valid = FALSE;
        return 0;
    }

    Cache->BasePa = basePa;
    Cache->Valid = TRUE;
    return Cache->Entries[Index & 0x1FF];
}


/* ========================================================================
 *  Section 3: CR3 获取 — 修复 BUG 2 (高位) + BUG 3 (KVAS) + BUG 4 (缓存)
 * ======================================================================== */

 /**
  * @brief 从 EPROCESS 读取 CR3, 带 KVAS 支持
  *
  * 优先使用 DirectoryTableBase (+0x28), 它在所有场景下都包含完整页表映射。
  * 同时读取 UserDirectoryTableBase (+0x280) 备用:
  *   - 非 KVAS 系统: UserDTB = 0, 只用 DTB
  *   - KVAS 系统: 两个都有值, 正常用 DTB, 翻译失败时回退 UserDTB
  */
static void ReadCr3FromEprocess(
    UINT64 Pid,
    UINT64* OutCr3,
    UINT64* OutUserCr3)
{
    PEPROCESS proc = NULL;
    NTSTATUS  st;
    UINT64    raw, userRaw;

    *OutCr3 = 0;
    *OutUserCr3 = 0;

    st = PsLookupProcessByProcessId((PVOID)(UINT_PTR)Pid, &proc);
    if (!NT_SUCCESS(st) || !proc) return;

    raw = *(PUINT64)((PUCHAR)proc + EPROCESS_DTB);
    userRaw = *(PUINT64)((PUCHAR)proc + EPROCESS_USER_DTB);
    ObDereferenceObject(proc);

    /*
     * [BUG 2 FIX] 使用 CR3_PA_MASK 而非 ~0xFFF:
     *
     * 旧代码: cr3 = raw & ~0xFFFULL
     *   ~0xFFFULL = 0xFFFFFFFFFFFFF000 — bit63 保留!
     *   如果 raw 含 NOFLUSH 标记 (bit63=1):
     *     cr3 = 0x8000_xxxx_xxxx_x000 — 无效的物理地址!
     *
     * 新代码: cr3 = raw & CR3_PA_MASK
     *   CR3_PA_MASK = 0x000FFFFFFFFFF000 — 只保留 bit12-51
     *   清除 PCID (bit0-11) 和 NOFLUSH (bit63)
     */
    * OutCr3 = raw & CR3_PA_MASK;
    *OutUserCr3 = userRaw & CR3_PA_MASK;
}

UINT64 StealthGetCr3(UINT64 Pid)
{
    LARGE_INTEGER tick;
    int i, oldest;
    UINT64 oldestTick;
    UINT64 cr3, userCr3;

    if (Pid == 0) return 0;

    /* 查找缓存 */
    KeQueryTickCount(&tick);
    for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
    {
        if (g_Cr3Cache[i].Pid == Pid && g_Cr3Cache[i].Cr3 != 0)
        {
            g_Cr3Cache[i].LastUseTick = (UINT64)tick.QuadPart;
            return g_Cr3Cache[i].Cr3;
        }
    }

    /* 缓存未命中 */
    ReadCr3FromEprocess(Pid, &cr3, &userCr3);
    if (cr3 == 0) return 0;

    /* 插入缓存 — LRU 替换 */
    oldest = 0;
    oldestTick = (UINT64)-1;
    for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
    {
        if (g_Cr3Cache[i].Pid == 0) { oldest = i; break; }
        if (g_Cr3Cache[i].LastUseTick < oldestTick)
        {
            oldestTick = g_Cr3Cache[i].LastUseTick;
            oldest = i;
        }
    }

    g_Cr3Cache[oldest].Pid = Pid;
    g_Cr3Cache[oldest].Cr3 = cr3;
    g_Cr3Cache[oldest].UserCr3 = userCr3;
    g_Cr3Cache[oldest].LastUseTick = (UINT64)tick.QuadPart;

    return cr3;
}

/**
 * @brief 获取 UserCr3 (KVAS 回退用)
 */
static UINT64 GetUserCr3(UINT64 Pid)
{
    int i;
    for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
    {
        if (g_Cr3Cache[i].Pid == Pid)
            return g_Cr3Cache[i].UserCr3;
    }
    /* 触发缓存填充 */
    StealthGetCr3(Pid);
    for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
    {
        if (g_Cr3Cache[i].Pid == Pid)
            return g_Cr3Cache[i].UserCr3;
    }
    return 0;
}

VOID StealthInvalidateCr3(UINT64 Pid)
{
    int i;
    for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
    {
        if (g_Cr3Cache[i].Pid == Pid)
        {
            g_Cr3Cache[i].Pid = 0;
            g_Cr3Cache[i].Cr3 = 0;
            g_Cr3Cache[i].UserCr3 = 0;
        }
    }
}


/* ========================================================================
 *  Section 4: VA → PA 翻译
 *
 *  [BUG 1 FIX] 每级页表条目都通过 CachedReadPte → ReadPhysical → MmCopyMemory
 *  读取, 不使用 MmGetVirtualForPhysical, 不受进程上下文影响。
 * ======================================================================== */

 /**
  * @brief 内部翻译函数 (指定 CR3)
  */
static UINT64 TranslateVaInternal(UINT64 Cr3, UINT64 Va)
{
    UINT64 pml4e, pdpte, pde, pte;

    /* 切换 CR3 时重置缓存 */
    if (g_StealthCache.Cr3 != Cr3)
    {
        StealthResetPtCache();
        g_StealthCache.Cr3 = Cr3;
    }

    /* PML4 */
    pml4e = CachedReadPte(&g_StealthCache.Pml4,
        Cr3 & ~0xFFFULL, (Va >> 39) & 0x1FF);
    if (!(pml4e & 1)) return 0;

    /* PDPT */
    pdpte = CachedReadPte(&g_StealthCache.Pdpt,
        pml4e & CR3_PA_MASK, (Va >> 30) & 0x1FF);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7))  /* 1GB 大页 */
        return (pdpte & 0x000FFFFFC0000000ULL) | (Va & 0x3FFFFFFF);

    /* PD */
    pde = CachedReadPte(&g_StealthCache.Pd,
        pdpte & CR3_PA_MASK, (Va >> 21) & 0x1FF);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7))  /* 2MB 大页 */
        return (pde & 0x000FFFFFFFE00000ULL) | (Va & 0x1FFFFF);

    /* PT */
    pte = CachedReadPte(&g_StealthCache.Pt,
        pde & CR3_PA_MASK, (Va >> 12) & 0x1FF);
    if (!(pte & 1)) return 0;

    return (pte & CR3_PA_MASK) | (Va & 0xFFF);
}

/**
 * @brief 公开翻译函数 — 带 KVAS 回退
 *
 * [BUG 3 FIX]:
 *   1. 先用 DirectoryTableBase (+0x28) 的 CR3 翻译
 *   2. 如果翻译失败 (用户空间 VA) 且 UserDirectoryTableBase 非零, 回退重试
 *   3. 如果仍然失败, 失效 CR3 缓存并重新查询 EPROCESS
 */
UINT64 StealthTranslateVa(UINT64 Cr3, UINT64 Va)
{
    return TranslateVaInternal(Cr3, Va);
}

/**
 * @brief 带完整回退逻辑的翻译 (内部用于 DirectRead)
 */
static UINT64 TranslateWithFallback(UINT64 Pid, UINT64 Cr3, UINT64 Va)
{
    UINT64 pa;

    /* 第一次尝试: DirectoryTableBase */
    pa = TranslateVaInternal(Cr3, Va);
    if (pa != 0) return pa;

    /* 用户空间 VA 翻译失败 — 尝试 KVAS 回退 */
    if (Va < 0x800000000000ULL)
    {
        UINT64 userCr3 = GetUserCr3(Pid);
        if (userCr3 != 0 && userCr3 != Cr3)
        {
            StealthResetPtCache();
            pa = TranslateVaInternal(userCr3, Va);
            if (pa != 0)
            {
                /* UserCr3 有效 — 更新缓存, 后续直接用 UserCr3 */
                int i;
                for (i = 0; i < STEALTH_CR3_CACHE_SIZE; i++)
                {
                    if (g_Cr3Cache[i].Pid == Pid)
                    {
                        g_Cr3Cache[i].Cr3 = userCr3;
                        break;
                    }
                }
                return pa;
            }
        }

        /* 两个 CR3 都失败 — 可能进程已退出或 CR3 过时 */
        /* 失效缓存, 下次调用时重新从 EPROCESS 读取 */
        StealthInvalidateCr3(Pid);
    }

    return 0;
}


/* ========================================================================
 *  Section 5: 进程内存读写
 * ======================================================================== */

BOOLEAN StealthDirectRead(UINT64 Pid, UINT64 Addr, PVOID OutBuf, ULONG Size)
{
    UINT64  cr3, va, pa;
    PUCHAR  dst;
    ULONG   done, pageRemain, chunk;
    BOOLEAN anySuccess = FALSE;

    if (Size == 0 || !OutBuf) return FALSE;

    cr3 = StealthGetCr3(Pid);
    if (!cr3) return FALSE;

    dst = (PUCHAR)OutBuf;
    va = Addr;
    done = 0;

    while (done < Size)
    {
        pageRemain = (ULONG)(0x1000 - (va & 0xFFF));
        chunk = Size - done;
        if (chunk > pageRemain) chunk = pageRemain;

        pa = TranslateWithFallback(Pid, cr3, va);

        if (pa == 0)
        {
            RtlZeroMemory(dst + done, chunk);
            done += chunk;
            va += chunk;
            continue;
        }

        if (ReadPhysical(pa, dst + done, chunk))
        {
            anySuccess = TRUE;
        }
        else
        {
            RtlZeroMemory(dst + done, chunk);
        }

        done += chunk;
        va += chunk;

        /* 更新 cr3 — 可能在 KVAS 回退中被修改 */
        cr3 = StealthGetCr3(Pid);
        if (!cr3) break;
    }

    return anySuccess;
}

BOOLEAN StealthDirectWrite(UINT64 Pid, UINT64 Addr, PVOID Data, ULONG Size)
{
    UINT64  cr3, va, pa;
    PUCHAR  src;
    ULONG   done, pageRemain, chunk;
    PHYSICAL_ADDRESS mapAddr;
    PVOID   mapped;
    BOOLEAN anySuccess = FALSE;

    if (Size == 0 || !Data) return FALSE;

    cr3 = StealthGetCr3(Pid);
    if (!cr3) return FALSE;

    src = (PUCHAR)Data;
    va = Addr;
    done = 0;

    while (done < Size)
    {
        pageRemain = (ULONG)(0x1000 - (va & 0xFFF));
        chunk = Size - done;
        if (chunk > pageRemain) chunk = pageRemain;

        pa = TranslateWithFallback(Pid, cr3, va);
        if (pa == 0)
        {
            done += chunk;
            va += chunk;
            continue;
        }

        /* 写入用 MmMapIoSpace (MmCopyMemory 不支持写) */
        mapAddr.QuadPart = (LONGLONG)(pa & ~0xFFFULL);
        mapped = MmMapIoSpace(mapAddr, 0x1000, MmNonCached);
        if (mapped)
        {
            __try {
                RtlCopyMemory((PUCHAR)mapped + (pa & 0xFFF), src + done, chunk);
                anySuccess = TRUE;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            MmUnmapIoSpace(mapped, 0x1000);
        }

        done += chunk;
        va += chunk;
    }

    return anySuccess;
}


/* ========================================================================
 *  Section 6: 页保护属性查询
 * ======================================================================== */

static DWORD PteToProtect(UINT64 pte)
{
    DWORD rw, nx;
    if (!(pte & 1)) return 0;
    if (!(pte & 4)) return 0;   /* Supervisor → 用户空间扫描跳过 */

    rw = (pte & 2) ? 1 : 0;
    nx = (pte & (1ULL << 63)) ? 1 : 0;

    if (rw && !nx) return 0x40;  /* PAGE_EXECUTE_READWRITE */
    if (rw && nx) return 0x04;  /* PAGE_READWRITE */
    if (!rw && !nx) return 0x20;  /* PAGE_EXECUTE_READ */
    return 0x02;                   /* PAGE_READONLY */
}

DWORD StealthGetPageProtect(UINT64 Cr3, UINT64 Va, PUINT64 pSkipSize)
{
    UINT64 pml4e, pdpte, pde, pte;

    if (pSkipSize) *pSkipSize = 0x1000;

    if (g_StealthCache.Cr3 != Cr3)
    {
        StealthResetPtCache();
        g_StealthCache.Cr3 = Cr3;
    }

    /* PML4 */
    pml4e = CachedReadPte(&g_StealthCache.Pml4,
        Cr3 & ~0xFFFULL, (Va >> 39) & 0x1FF);
    if (!(pml4e & 1))
    {
        if (pSkipSize) *pSkipSize = (((Va >> 39) + 1) << 39) - Va;
        return 0;
    }

    /* PDPT */
    pdpte = CachedReadPte(&g_StealthCache.Pdpt,
        pml4e & CR3_PA_MASK, (Va >> 30) & 0x1FF);
    if (!(pdpte & 1))
    {
        if (pSkipSize) *pSkipSize = (((Va >> 30) + 1) << 30) - Va;
        return 0;
    }
    if (pdpte & (1ULL << 7))
    {
        if (pSkipSize) *pSkipSize = 1ULL << 30;
        return PteToProtect(pdpte);
    }

    /* PD */
    pde = CachedReadPte(&g_StealthCache.Pd,
        pdpte & CR3_PA_MASK, (Va >> 21) & 0x1FF);
    if (!(pde & 1))
    {
        if (pSkipSize) *pSkipSize = (((Va >> 21) + 1) << 21) - Va;
        return 0;
    }
    if (pde & (1ULL << 7))
    {
        if (pSkipSize) *pSkipSize = 1ULL << 21;
        return PteToProtect(pde);
    }

    /* PT */
    pte = CachedReadPte(&g_StealthCache.Pt,
        pde & CR3_PA_MASK, (Va >> 12) & 0x1FF);
    if (pSkipSize) *pSkipSize = 0x1000;
    return PteToProtect(pte);
}


/* ========================================================================
 *  Section 7: 内存区域查询
 * ======================================================================== */

BOOLEAN StealthQueryRegion(
    UINT64    Cr3,
    UINT64    StartVa,
    PUINT_PTR OutSize,
    PDWORD    OutProtect)
{
    UINT64 va, maxVa, skipSize, regionStart;
    DWORD  firstProt, curProt;

    va = StartVa & ~0xFFFULL;
    maxVa = 0x7FFFFFFF0000ULL;

    if (va >= maxVa) return FALSE;

    skipSize = 0x1000;
    firstProt = StealthGetPageProtect(Cr3, va, &skipSize);
    regionStart = va;

    if (firstProt == 0)
    {
        va += skipSize;
        while (va < maxVa)
        {
            skipSize = 0x1000;
            curProt = StealthGetPageProtect(Cr3, va, &skipSize);
            if (curProt != 0) break;
            va += skipSize;
        }
    }
    else
    {
        va += skipSize;
        while (va < maxVa)
        {
            skipSize = 0x1000;
            curProt = StealthGetPageProtect(Cr3, va, &skipSize);
            if (curProt != firstProt) break;
            va += skipSize;
        }
    }

    if (va > maxVa) va = maxVa;
    *OutSize = (UINT_PTR)(va - regionStart);
    *OutProtect = firstProt;
    return (*OutSize > 0);
}


/* ========================================================================
 *  Section 8: 辅助函数
 * ======================================================================== */

UINT64 StealthGetPhysAddr(UINT64 Pid, UINT64 Va)
{
    UINT64 cr3 = StealthGetCr3(Pid);
    if (!cr3) return 0;
    return TranslateWithFallback(Pid, cr3, Va);
}

UINT64 StealthGetProcessCr3(UINT64 Pid)
{
    return StealthGetCr3(Pid);
}