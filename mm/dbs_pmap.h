#ifndef DBS_ULONGMAP_H
#define DBS_ULONGMAP_H

#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/barrier.h>
#include <asm/msr.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/printk.h>
#include <linux/xarray.h>

extern struct xarray dbs_pfn_map; // Global XArray for storing page frame numbers to virtual addresses

/* zeroswap */
#define MAX_TRACKED_PAGES (1UL << 28)  // 4 million pages

typedef struct {
    long *pages; //long
    size_t entry_count;
} pages_va_map_t;

extern pages_va_map_t *p2va_map;
extern pages_va_map_t *va2sec_map;


static inline pages_va_map_t *pages_va_map_create(size_t max_pages)
{
    pages_va_map_t *um = kmalloc(sizeof(pages_va_map_t), GFP_KERNEL & ~__GFP_RECLAIM);
    if (!um)
        return NULL;

    um->entry_count = max_pages;
    um->pages = vzalloc(max_pages * sizeof(long));
    if (!um->pages) {
        kfree(um);
        return NULL;
    }

    return um;
}

static inline void pages_va_map_set(pages_va_map_t *um, uint64_t addr, long value) //,bool log, bool is_out
{
    size_t page_idx = (addr >> PAGE_SHIFT) & (MAX_TRACKED_PAGES - 1);
    /*u64 t_ns = ktime_get_ns();
    u64 sec = t_ns / 1000000000ULL;
    u64 nsec = t_ns % 1000000000ULL;*/
    /*if (log) //MAHOP
        pr_info("HEVT,%lx,%llu,%llu,%llu.%09llu,%s\n", addr, page_idx,value,sec, nsec, is_out?"OUT":"IN");
    mb();
    rmb();
    smp_wmb();*/ 
    if (page_idx < um->entry_count)
        um->pages[page_idx] = value;
    /*smp_wmb();
    mb(); rmb();*/ //MAHOP
    
}

static inline void pages_va_map_set_folio(pages_va_map_t *um, uint64_t addr, long value) //,bool log, bool is_out
{
    size_t page_idx = (addr ) & (MAX_TRACKED_PAGES - 1);
    /*u64 t_ns = ktime_get_ns();
    u64 sec = t_ns / 1000000000ULL;
    u64 nsec = t_ns % 1000000000ULL;*/
    /*if (log) //MAHOP
        pr_info("HEVT,%lx,%llu,%llu,%llu.%09llu,%s\n", addr, page_idx,value,sec, nsec, is_out?"OUT":"IN");
    mb();
    rmb();
    smp_wmb();*/ 
    if (page_idx < um->entry_count)
        um->pages[page_idx] = value;
    /*smp_wmb();
    mb(); rmb();*/ //MAHOP
    
}
static inline long pages_va_map_get_folio(pages_va_map_t *um, uint64_t addr)
{
    size_t page_idx = (addr ) & (MAX_TRACKED_PAGES - 1);
    if (page_idx < um->entry_count)
        return um->pages[page_idx];
    return 0;
}

static inline long pages_va_map_get(pages_va_map_t *um, uint64_t addr)
{
    size_t page_idx = (addr >> PAGE_SHIFT) & (MAX_TRACKED_PAGES - 1);
    if (page_idx < um->entry_count)
        return um->pages[page_idx];
    return 0;
}

static inline void pages_va_map_destroy(pages_va_map_t *um)
{
    if (um) {
        if (um->pages)
            vfree(um->pages);
        kfree(um);
    }
}

#endif /* DBS_ULONGMAP_H */