/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_DCACHE_H
#define __LINUX_DCACHE_H

#include <stdint.h>
#include <ksyms.h>

struct path;
struct vfsmount;

char *kfunc_def(d_path)(const struct path *path, char *buf, int buflen);
char *kfunc_def(simple_dname)(struct dentry *dentry, char *buffer, int buflen);
char *kfunc_def(dynamic_dname)(struct dentry *dentry, char *buffer, int buflen, const char *fmt, ...);
char *kfunc_def(dentry_path_raw)(struct dentry *dentry, char *buf, int buflen);
char *kfunc_def(dentry_path)(struct dentry *dentry, char *buf, int buflen);

char *d_path(const struct path *path, char *buf, int buflen);
char *simple_dname(struct dentry *dentry, char *buffer, int buflen);
char *dynamic_dname(struct dentry *dentry, char *buffer, int buflen, const char *fmt, ...);
char *dentry_path_raw(struct dentry *dentry, char *buf, int buflen);
char *dentry_path(struct dentry *dentry, char *buf, int buflen);

#endif