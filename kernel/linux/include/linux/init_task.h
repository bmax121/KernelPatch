#ifndef _LINUX_INIT_TASK_H
#define _LINUX_INIT_TASK_H

extern union thread_union *kvar(init_thread_union);
extern int kvlen(init_thread_union);

extern struct task_struct *kvar(init_task);
extern int kvlen(init_task);

extern unsigned long *kvar(init_stack);
extern int kvlen(init_stack);

extern struct cred *kvar(init_cred);
extern int kvlen(init_cred);
extern struct group_info *kvar(init_groups);

// extern struct files_struct *init_files;
// extern struct fs_struct *init_fs;
// extern struct nsproxy *init_nsproxy;
// extern struct group_info *init_groups;

#endif