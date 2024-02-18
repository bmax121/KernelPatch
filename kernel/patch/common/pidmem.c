#include "pidmem.h"

#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm_types.h>
#include <linux/errno.h>
#include <linux/sched/mm.h>
#include <pgtable.h>
#include <linux/err.h>

uintptr_t pgtable_walker_entry(uintptr_t pgd_addr, uintptr_t va)
{
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd_addr;
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
    return pxd_entry_va;
}

phys_addr_t pid_virt_to_phys(pid_t pid, uintptr_t vaddr)
{
    if (mm_struct_offset.pgd_offset < 0) {
        return -EFAULT;
    }

    struct task_struct *task = find_get_task_by_vpid(pid);
    if (!task) {
        logkfe("no such pid: %d\n", pid);
        return -ESRCH;
    }

    int rc = 0;

    struct mm_struct *mm = get_task_mm(task);
    if (IS_ERR(mm)) {
        // todo
    }
    logkd("aaaaaaaaaaaaa %llx\n", mm);
    uintptr_t pgd = *(uintptr_t *)((uintptr_t)mm + mm_struct_offset.pgd_offset);
    logkd("aaaaaaaaaaaaa %llx\n", pgd);

    uintptr_t entry = pgtable_walker_entry(pgd, vaddr);
    logkd("aaaaaaaaaaaaa %llx\n", entry);
    logkd("aaaaaaaaaaaaa %llx\n", *(uintptr_t *)entry);

    mmput(mm);

out:
    return rc;
}