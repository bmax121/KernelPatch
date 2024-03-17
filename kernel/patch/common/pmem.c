#include "pidmem.h"

#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm_types.h>
#include <linux/errno.h>
#include <linux/sched/mm.h>
#include <pgtable.h>
#include <linux/err.h>

//void free_task(struct task_struct *tsk)
// EXPORT_SYMBOL(free_task);
// void __put_task_struct(struct task_struct *tsk)
//EXPORT_SYMBOL_GPL(__put_task_struct);

uint64_t *local_pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys(pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;

    for (int64_t lv = 4 - page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va) return 0;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else { // invalid
            return 0;
        }
        //
        pxd_va = phys_to_virt(pxd_pa);
        if (block_lv) {
            break;
        }
    }
#if 1
    uint64_t left_bit = page_shift + (block_lv ? (3 - block_lv) * pxd_bits : 0);
    uint64_t tpa = pxd_pa + (va & ((1u << left_bit) - 1));
    uint64_t tlva = phys_to_virt(tpa);
    uint64_t tkimg = phys_to_kimg(tpa);
    // if (tlva != va && tkimg != va) {
    //     return 0;
    // }
    logkd("tpa: %llx, tlva: %llx, tkimg: %llx\n", tpa, tlva, tkimg);
#endif
    return (uint64_t *)pxd_entry_va;
}

phys_addr_t pid_virt_to_phys(pid_t pid, uintptr_t vaddr)
{
    if (mm_struct_offset.pgd_offset < 0) {
        return -EFAULT;
    }

    int rc = 0;

    logkd("pid: %llx, vaddr: %llx\n", pid, vaddr);
    logkd("aaaa %llx\n", kfunc(find_get_task_by_vpid));

    // struct task_struct *task = find_get_task_by_vpid(pid);
    struct task_struct *task = find_task_by_vpid(pid);
    if (!task) {
        logkfe("no such pid: %d\n", pid);
        return -ESRCH;
    }

    logkd("task: %llx\n", task);

    struct mm_struct *mm = get_task_mm(task);
    if (!mm || IS_ERR(mm)) {
        // todo
    }

    logkd("mm: %llx\n", mm);

    uintptr_t pgd = *(uintptr_t *)((uintptr_t)mm + mm_struct_offset.pgd_offset);
    logkd("pgd: %llx\n", pgd);

    for (uintptr_t i = pgd; i < pgd + 512 * 8; i += 8) {
        logkd("pgd i: %llx, val: %llx\n", i, *(uintptr_t *)i);
    }

    uintptr_t *entry = local_pgtable_entry(pgd, vaddr);
    logkd("entry: %llx\n", entry);
    logkd("entry value: %llx\n", *(uintptr_t *)entry);

    // remap_pfn_range or direct modify pgtable

    mmput(mm);
    return rc;
}