#include "pidmem.h"

#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm_types.h>
#include <linux/errno.h>
#include <linux/sched/mm.h>
#include <pgtable.h>
#include <linux/err.h>

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
    uintptr_t pgd = *(uintptr_t *)((uintptr_t)mm + mm_struct_offset.pgd_offset);
    uintptr_t entry = pgtable_entry(pgd, vaddr);

    // remap_pfn_range or direct modify pgtable

    mmput(mm);
out:
    return rc;
}