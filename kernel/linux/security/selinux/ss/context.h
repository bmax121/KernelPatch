/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A security context is a set of security attributes
 * associated with each subject and object controlled
 * by the security policy.  Security contexts are
  * externally represented as variable-length strings
 * that can be interpreted by a user or application
 * with an understanding of the security policy.
 * Internally, the security server uses a simple
 * structure.  This structure is private to the
 * security server and can be changed without affecting
 * clients of the security server.
 *
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
 */
#ifndef _SS_CONTEXT_H_
#define _SS_CONTEXT_H_

#include <ktypes.h>
#include "mls_types.h"

/*
 * A security context consists of an authenticated user
 * identity, a role, a type and a MLS range.
 */
struct context
{
    u32 user;
    u32 role;
    u32 type;
    u32 len; /* length of string in bytes */
    struct mls_range range;
    char *str; /* string representation if context cannot be mapped. */
};

#endif