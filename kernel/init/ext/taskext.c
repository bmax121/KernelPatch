#include <taskext.h>

#include <asm/current.h>

struct task_ext *prepare_task_ext(struct task_struct *task)
{
    struct task_ext *ext = get_task_ext(task);
    ext->magic = TASK_EXT_MAGIC;
    ext->task = task;
    ext->emagic = TASK_EXT_EMAGIC;
    return ext;
}