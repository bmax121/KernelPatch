/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <log.h>
#include <stdbool.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/vmalloc.h>
#include <baselib.h>
#include <linux/pid.h>
#include <asm/current.h>
#include <linux/security.h>
#include <syscall.h>
#include <uapi/linux/prctl.h>
#include <uapi/linux/magic.h>
#include <linux/capability.h>
#include <linux/seccomp.h>
#include <ksyms.h>
#include <pgtable.h>
#include <symbol.h>
#include <asm/processor.h>

#define TASK_COMM_LEN 16

#define TASK_STRUCT_MAX_SIZE 0x1800
#define THREAD_INFO_MAX_SIZE 0x90
#define CRED_MAX_SIZE 0x100

struct task_struct_offset task_struct_offset = {
    .pid_offset = -1,
    .tgid_offset = -1,
    .thread_pid_offset = -1,
    .ptracer_cred_offset = -1,
    .real_cred_offset = -1,
    .cred_offset = -1,
    .fs_offset = -1,
    .files_offset = -1,
    .loginuid_offset = -1,
    .sessionid_offset = -1,
    .comm_offset = -1,
    .seccomp_offset = -1,
    .security_offset = -1,
    .stack_offset = -1,
    .tasks_offset = -1,
};
KP_EXPORT_SYMBOL(task_struct_offset);

struct cred_offset cred_offset = {
    .usage_offset = -1,
    .subscribers_offset = -1,
    .magic_offset = -1,
    .uid_offset = -1,
    .gid_offset = -1,
    .suid_offset = -1,
    .sgid_offset = -1,
    .euid_offset = -1,
    .egid_offset = -1,
    .fsuid_offset = -1,
    .fsgid_offset = -1,
    .securebits_offset = -1,
    .cap_inheritable_offset = -1,
    .cap_permitted_offset = -1,
    .cap_effective_offset = -1,
    .cap_bset_offset = -1,
    .cap_ambient_offset = -1,

    .user_offset = -1,
    .user_ns_offset = -1,
    .ucounts_offset = -1,
    .group_info_offset = -1,

    .session_keyring_offset = -1,
    .process_keyring_offset = -1,
    .thread_keyring_offset = -1,
    .request_key_auth_offset = -1,

    .security_offset = -1,

    .rcu_offset = -1,
};
KP_EXPORT_SYMBOL(cred_offset);

struct task_struct *init_task = 0;
KP_EXPORT_SYMBOL(init_task);

const struct cred *init_cred = 0;
KP_EXPORT_SYMBOL(init_cred);

int thread_size = 0;
KP_EXPORT_SYMBOL(thread_size);

int thread_info_in_task = 0;
KP_EXPORT_SYMBOL(thread_info_in_task);

int sp_el0_is_current = 0;
KP_EXPORT_SYMBOL(sp_el0_is_current);

int sp_el0_is_thread_info = 0;
KP_EXPORT_SYMBOL(sp_el0_is_thread_info);

int task_in_thread_info_offset = -1;
KP_EXPORT_SYMBOL(task_in_thread_info_offset);

int stack_in_task_offset = -1;
KP_EXPORT_SYMBOL(stack_in_task_offset);

int stack_end_offset = 0x90;
KP_EXPORT_SYMBOL(stack_end_offset);

static int16_t *bl_list = 0;
static int bl_cap = 0;

static void reinit_bllist(int num)
{
    bl_cap = num;
    bl_list = (int16_t *)vmalloc(bl_cap * sizeof(int16_t));
    for (int i = 0; i < bl_cap; i++) {
        bl_list[i] = -1;
    }
}

static void uninit_bllist()
{
    bl_cap = 0;
    vfree(bl_list);
}

static int is_bl(int16_t off)
{
    for (int i = 0; i < bl_cap; i++) {
        if (bl_list[i] < 0) break;
        if (bl_list[i] == off) return 1;
    }
    return 0;
}

static void add_bll(int16_t off, int16_t size)
{
    for (int i = 0; i < bl_cap; i++) {
        if (bl_list[i] < 0) {
            bl_list[i] = off;
            if (size == 8) bl_list[i + 1] = off + 4;
            break;
        }
    }
}

int resolve_cred_offset()
{
    log_boot("struct cred: \n");

    reinit_bllist(128);

    struct cred *cred = (struct cred *)vmalloc(CRED_MAX_SIZE);
    struct cred *cred1 = (struct cred *)vmalloc(CRED_MAX_SIZE);
    struct task_struct *task = vmalloc(TASK_STRUCT_MAX_SIZE);
    lib_memcpy(cred, init_cred, CRED_MAX_SIZE);
    lib_memcpy(cred1, init_cred, CRED_MAX_SIZE);
    lib_memcpy(task, init_task, TASK_STRUCT_MAX_SIZE);

    *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset) = cred;
    *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset) = cred;

    const struct task_struct *backup = override_current(task);

    // cap_inheritable, cap_permitted, cap_effective
    kernel_cap_t effective, inheritable, permitted;
    cap_capget(task, &effective, &inheritable, &permitted);
    full_cap.val = effective.val;
    log_boot("    full_cap capability: %x\n", full_cap.val);

    kernel_cap_t new_cap_e = { 0xff }, new_cap_i = { 0xf }, new_cap_p = { 0xfff };
    cap_capset(cred1, cred, &new_cap_e, &new_cap_i, &new_cap_p);

    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(kernel_cap_t)) {
        if (is_bl(i)) continue;
        kernel_cap_t cap = *(kernel_cap_t *)((uintptr_t)cred + i);
        kernel_cap_t cap1 = *(kernel_cap_t *)((uintptr_t)cred1 + i);
        if (cap.val == effective.val && cap1.val == new_cap_e.val) {
            cred_offset.cap_effective_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
            continue;
        }
        if (cap.val == inheritable.val && cap1.val == new_cap_i.val) {
            cred_offset.cap_inheritable_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
            continue;
        }
        if (cap.val == permitted.val && cap1.val == new_cap_p.val) {
            cred_offset.cap_permitted_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
            continue;
        }
    }

    // cap_bset
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(kernel_cap_t)) {
        if (is_bl(i)) continue;
        kernel_cap_t cap1 = *(kernel_cap_t *)((uintptr_t)cred1 + i);
        if (cap1.val == effective.val) {
            cred_offset.cap_bset_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
        }
    }
    log_boot("    cap_effective offset: %x\n", cred_offset.cap_effective_offset);
    log_boot("    cap_inheritable offset: %x\n", cred_offset.cap_inheritable_offset);
    log_boot("    cap_permitted offset: %x\n", cred_offset.cap_permitted_offset);
    log_boot("    cap_bset offset: %x\n", cred_offset.cap_bset_offset);

    // securebits
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(unsigned)) {
        if (is_bl(i)) continue;
        unsigned *sbitsp = (unsigned *)((uintptr_t)cred + i);
        unsigned oribits = *sbitsp;
        *sbitsp = 1158;
        unsigned sbits = cap_task_prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
        if (sbits != 1158) {
            *sbitsp = oribits;
            continue;
        }
        *sbitsp = oribits;
        cred_offset.securebits_offset = i;
        add_bll(i, sizeof(unsigned));
        break;
    }
    log_boot("    securebits offset: %x\n", cred_offset.securebits_offset);

    // euid, uid, egid, gid
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(uid_t)) {
        if (is_bl(i)) continue;
        uid_t *uidp = (uid_t *)((uintptr_t)cred + i);
        if (*uidp) continue;
        *uidp = 1158;
        if (raw_syscall0(__NR_geteuid) == 1158) {
            cred_offset.euid_offset = i;
        } else if (raw_syscall0(__NR_getuid) == 1158) {
            cred_offset.uid_offset = i;
        } else if (raw_syscall0(__NR_getegid) == 1158) {
            cred_offset.egid_offset = i;
        } else if (raw_syscall0(__NR_getgid) == 1158) {
            cred_offset.gid_offset = i;
        } else {
            *uidp = 0;
            continue;
        }
        *uidp = 0;
        add_bll(i, sizeof(uid_t));
    }
    log_boot("    uid offset: %x\n", cred_offset.uid_offset);
    log_boot("    euid offset: %x\n", cred_offset.euid_offset);
    log_boot("    gid offset: %x\n", cred_offset.gid_offset);
    log_boot("    egid offset: %x\n", cred_offset.egid_offset);

    // fsuid
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(uid_t)) {
        if (is_bl(i)) continue;
        uid_t *uidp = (uid_t *)((uintptr_t)cred + i);
        uid_t backup = *uidp;
        *uidp = 1158;
        uid_t old_uid = raw_syscall1(__NR_setfsuid, -1);
        *uidp = backup;
        if (old_uid == 1158) {
            cred_offset.fsuid_offset = i;
            add_bll(i, sizeof(uid_t));
            break;
        }
    }
    log_boot("    fsuid offset: %x\n", cred_offset.fsuid_offset);

    // fsgid
    struct cred *new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(gid_t)) {
        if (is_bl(i)) continue;
        gid_t *gidp = (gid_t *)((uintptr_t)new_cred + i);
        gid_t backup = *gidp;
        *gidp = 1158;
        gid_t old_gid = raw_syscall1(__NR_setfsgid, -1);
        *gidp = backup;
        if (old_gid == 1158) {
            cred_offset.fsgid_offset = i;
            add_bll(i, sizeof(gid_t));
            break;
        }
    }
    log_boot("    fsgid offset: %x\n", cred_offset.fsgid_offset);

    // suid
    raw_syscall3(__NR_setresuid, 0, 0, 1158);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(uid_t)) {
        if (is_bl(i)) continue;
        uid_t *uidp = (uid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.suid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(uid_t));
            break;
        }
    }
    log_boot("    suid offset: %x\n", cred_offset.suid_offset);

    // sgid
    raw_syscall3(__NR_setresgid, 0, 0, 1158);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(gid_t)) {
        if (is_bl(i)) continue;
        gid_t *uidp = (gid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.sgid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(gid_t));
            break;
        }
    }
    log_boot("    sgid offset: %x\n", cred_offset.sgid_offset);

    // cap_ambient
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_permitted_offset) = full_cap;
    *(unsigned *)((uintptr_t)new_cred + cred_offset.securebits_offset) = 0;
    cap_task_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 0xf, 0, 0);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(kernel_cap_t)) {
        if (is_bl(i)) continue;
        kernel_cap_t cap = *(kernel_cap_t *)((uintptr_t)cred + i);
        kernel_cap_t new_cap = *(kernel_cap_t *)((uintptr_t)new_cred + i);
        if (!cap.val && new_cap.val == (1 << 0xf)) {
            cred_offset.cap_ambient_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
        }
    }
    log_boot("    cap_ambient offset: %x\n", cred_offset.cap_ambient_offset);

    revert_current(backup);

    vfree(cred);
    vfree(cred1);
    vfree(task);

    uninit_bllist();
    return 0;
}

static int find_swapper_comm_offset(uint64_t start, int size)
{
    if (!is_kimg_range(start) || !is_kimg_range(start + size)) return -1;
    char swapper_comm[TASK_COMM_LEN] = "swapper";
    char swapper_comm_1[TASK_COMM_LEN] = "swapper/0";
    for (uint64_t i = start; i < start + size; i += 8) {
        if (!lib_strcmp(swapper_comm, (char *)i) || !lib_strcmp(swapper_comm_1, (char *)i)) {
            return i - start;
        }
    }
    return -1;
}

int resolve_task_offset()
{
    log_boot("struct task_struct: \n");

    struct task_struct *task = (struct task_struct *)vmalloc(TASK_STRUCT_MAX_SIZE);
    lib_memcpy(task, init_task, TASK_STRUCT_MAX_SIZE);

    const struct task_struct *backup = override_current(task);

    // init_cred
    int cred_offset[2];
    int cred_offset_idx = 0;
    init_cred = get_task_cred(init_task); // todo: get_task_cred not export
    log_boot("    init_cred addr: %llx\n", init_cred);
    for (uintptr_t i = (uintptr_t)init_task; i < (uintptr_t)init_task + TASK_STRUCT_MAX_SIZE; i += sizeof(uintptr_t)) {
        uintptr_t val = *(uintptr_t *)i;
        if (val == (uintptr_t)init_cred) {
            cred_offset[cred_offset_idx++] = i - (uintptr_t)init_task;
            if (cred_offset_idx >= 2) break;
        }
    }

    char flag_cred[CRED_MAX_SIZE];
    lib_memcpy(flag_cred, init_cred, sizeof(flag_cred));
    *(uintptr_t *)((uintptr_t)init_task + cred_offset[0]) = (uintptr_t)flag_cred;
    if ((uintptr_t)init_cred == (uintptr_t)flag_cred) {
        task_struct_offset.real_cred_offset = cred_offset[0];
        task_struct_offset.cred_offset = cred_offset[1];
    } else {
        task_struct_offset.real_cred_offset = cred_offset[1];
        task_struct_offset.cred_offset = cred_offset[0];
    }
    *(uintptr_t *)((uintptr_t)init_task + cred_offset[0]) = (uintptr_t)init_cred;

    log_boot("    cred offset: %x\n", task_struct_offset.cred_offset);
    log_boot("    real_cred offset: %x\n", task_struct_offset.real_cred_offset);

    // seccomp
    if (kfunc(prctl_get_seccomp)) {
        for (uintptr_t i = (uintptr_t)task; i < (uintptr_t)task + TASK_STRUCT_MAX_SIZE; i += sizeof(uintptr_t)) {
            int *modep = (int *)i;
            int mode_back = *modep;
            if (mode_back) continue;
            *modep = 1158;
            int mode = prctl_get_seccomp();
            if (mode == 1158) {
                task_struct_offset.seccomp_offset = i - (uintptr_t)task;
            }
            *modep = mode_back;
        }
    }
    log_boot("    seccomp offset: %x\n", task_struct_offset.seccomp_offset);

    revert_current(backup);
    vfree(task);
    return 0;
}

int resolve_current()
{
    log_boot("current: \n");
    uint64_t sp_el0, sp;
    asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
    asm volatile("mov %0, sp" : "=r"(sp));

    log_boot("    sp_el0: %llx\n", sp_el0);
    log_boot("    sp: %llx\n", sp);

    // default value
    sp_el0_is_current = 0;
    sp_el0_is_thread_info = 0;

    init_task = (struct task_struct *)kallsyms_lookup_name("init_task");
    uint64_t init_thread_union_addr = kallsyms_lookup_name("init_thread_union");
#if 0
    init_task = 0;
    init_thread_union_addr = 0;
#endif

    log_boot("    init_task lookup: %llx\n", init_task);
    log_boot("    init_thread_union lookup: %llx\n", init_thread_union_addr);

    if (is_kimg_range(sp_el0)) {
        if (sp_el0 == init_thread_union_addr) {
            sp_el0_is_thread_info = 1;
            log_boot("    sp_el0: current_thread_info\n");
        } else if ((uint64_t)init_task == sp_el0 || (sp_el0 & (page_size - 1)) ||
                   (task_struct_offset.comm_offset = find_swapper_comm_offset(sp_el0, TASK_STRUCT_MAX_SIZE)) > 0) {
            sp_el0_is_current = 1;
            init_task = (struct task_struct *)sp_el0;

            log_boot("    sp_el0: current\n");
            log_boot("    init_task addr: %llx\n", init_task);
            if (task_struct_offset.comm_offset > 0) {
                log_boot("    comm_offset of task: %x\n", task_struct_offset.comm_offset);
            }
        } else {
            sp_el0_is_thread_info = 1;
            log_boot("    sp_el0: current_thread_info\n");
        }
    } else {
        // use sp
        log_boot("    sp_el0: useless\n");
    }

    // THREAD_SIZE and end_of_stack and CONFIG_THREAD_INFO_IN_TASK
    // don't worry, we use little stack until here
    int thread_shift_cand[] = { 14, 15, 16 };
    for (int i = 0; i < sizeof(thread_shift_cand) / sizeof(thread_shift_cand[0]); i++) {
        int tsz = 1 << thread_shift_cand[i];
        uint64_t sp_low = sp & ~(tsz - 1);
        // uint64_t sp_high = sp_low + tsz; // user_stack_pointer
        uint64_t psp = sp_low;
        for (; psp < sp_low + THREAD_INFO_MAX_SIZE; psp += 8) {
            if (*(uint64_t *)psp == STACK_END_MAGIC) {
                if (psp == sp_low) {
                    thread_size = tsz;
                    stack_end_offset = 0;
                    thread_info_in_task = 1;
                } else {
                    thread_size = tsz;
                    stack_end_offset = psp - sp_low;
                    thread_info_in_task = 0;
                }
                break;
            }
        }
        if (thread_size > 0) {
            log_boot("    init stack end: %llx\n", psp);
            break;
        }
    }

    log_boot("    thread_size: %x\n", thread_size);
    log_boot("    stack_end_offset: %x\n", stack_end_offset);
    log_boot("    thread_info_in_task: %x\n", thread_info_in_task);

    // task_in_thread_info_offset, 16 generally, see thread_info_be490
    if (!thread_info_in_task) {
        uint64_t thread_info_addr = (uint64_t)current_thread_info_sp();
        if (init_task) {
            for (uint64_t ptr = thread_info_addr; ptr < thread_info_addr + stack_end_offset; ptr += sizeof(uint64_t)) {
                uint64_t pv = *(uint64_t *)ptr;
                if (pv == (uint64_t)init_task) {
                    task_in_thread_info_offset = ptr - thread_info_addr;
                    break;
                }
            }
        } else { // unlikely
            for (uint64_t ptr = thread_info_addr; ptr < thread_info_addr + stack_end_offset; ptr += sizeof(uint64_t)) {
                uint64_t pv = *(uint64_t *)ptr;
                task_struct_offset.comm_offset = find_swapper_comm_offset(pv, TASK_STRUCT_MAX_SIZE);
                if (task_struct_offset.comm_offset > 0) {
                    init_task = (struct task_struct *)pv;
                    task_in_thread_info_offset = ptr - thread_info_addr;
                    log_boot("    init_task addr: %llx\n", init_task);
                    log_boot("    comm_offset of task: %x\n", task_struct_offset.comm_offset);
                }
            }
        }
        log_boot("    task_in_thread_info_offset: %x\n", task_in_thread_info_offset);
    }

    if (task_struct_offset.comm_offset <= 0) {
        task_struct_offset.comm_offset = find_swapper_comm_offset((uint64_t)init_task, TASK_STRUCT_MAX_SIZE);
        log_boot("    comm_offset of task: %x\n", task_struct_offset.comm_offset);
    }

    // stack,
    uint64_t stack_base = (sp & ~(thread_size - 1));
    for (uintptr_t i = (uintptr_t)init_task; i < (uintptr_t)init_task + TASK_STRUCT_MAX_SIZE; i += sizeof(uintptr_t)) {
        uintptr_t val = *(uintptr_t *)i;
        if (stack_base == val) {
            stack_in_task_offset = i - (uintptr_t)init_task;
            task_struct_offset.stack_offset = stack_in_task_offset;
            break;
        }
    }
    log_boot("    stack offset of task: %x\n", task_struct_offset.stack_offset);

    return 0;
}

int resolve_struct()
{
    full_cap = CAP_FULL_SET;

    int err = 0;
    if ((err = resolve_current())) goto out;
    if ((err = resolve_task_offset())) goto out;
    if ((err = resolve_cred_offset())) goto out;

out:
    return err;
}
