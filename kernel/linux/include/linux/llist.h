/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LLIST_H
#define LLIST_H

#include <stddef.h>

struct llist_head
{
    struct llist_node *first;
};

struct llist_node
{
    struct llist_node *next;
};

#define LLIST_HEAD_INIT(name) \
    {                         \
        NULL                  \
    }
#define LLIST_HEAD(name) struct llist_head name = LLIST_HEAD_INIT(name)

static inline void init_llist_head(struct llist_head *list)
{
    list->first = NULL;
}

#endif