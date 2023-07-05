#ifndef _LINUX__INIT_TASK_H
#define _LINUX__INIT_TASK_H

extern struct files_struct *init_files;
extern struct fs_struct *init_fs;
extern struct nsproxy *init_nsproxy;
extern struct group_info *init_groups;
extern struct cred *init_cred;

#endif