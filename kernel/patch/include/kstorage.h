/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_KSTORAGE_H_
#define _KP_KSTORAGE_H_

#include <uapi/scdefs.h>
#include <ktypes.h>
#include <stdbool.h>

struct kstorage
{
    struct list_head list;
    struct rcu_head rcu;

    int gid;
    long did;
    int dlen;
    char data[0];
};

int try_alloc_kstroage_group();

int kstorage_group_size(int gid);

int write_kstorage(int gid, long did, void *data, int offset, int len, bool data_is_user);

// must surround with rcu read lock
const struct kstorage *get_kstorage(int gid, long did);

typedef int (*on_kstorage_cb)(struct kstroage *kstorage, void *udata);
int on_each_kstorage_elem(int gid, on_kstorage_cb cb, void *udata);

const struct kstorage *get_kstorage(int gid, long did);

int read_kstorage(int gid, long did, void *data, int offset, int len, bool data_is_user);

int remove_kstorage(int gid, long did);

#endif