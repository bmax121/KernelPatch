#include <init/struct.h>

#include <log.h>
#include <stdbool.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <asm/current.h>
#include <linux/security.h>
#include <syscall/syscall.h>
#include <uapi/linux/prctl.h>
#include <linux/capability.h>
#include <init/ksyms.h>

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
    .seccomp_offset = -1,
    .security_offset = -1,
};

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

static int16_t *bl_list = 0;
static int bl_cap = 0;

static void reinit_bllist(int num)
{
    bl_cap = num;
    bl_list = (int16_t *)vmalloc(bl_cap * sizeof(int16_t));
    for (int i = 0; i < bl_cap; i++) { bl_list[i] = -1; }
}

static void uninit_bllist()
{
    vfree(bl_list);
    bl_cap = 0;
}

static bool is_bl(int16_t off)
{
    for (int i = 0; i < bl_cap; i++) {
        if (bl_list[i] < 0) break;
        if (bl_list[i] == off) return true;
    }
    return false;
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

// todo:
int build_cred_offset()
{
    int cred_len = kvlen(init_cred);
    int task_len = kvlen(init_task);

    if (task_len <= 0 || cred_len <= 0) {
        logke("init_task or init_cred length unknown\n");
        return -1;
    }

    uintptr_t backup = (uintptr_t)current;

    reinit_bllist(128);

    struct task_struct *task = (struct task_struct *)vmalloc(task_len);
    memcpy(task, kvar(init_task), task_len);
    struct cred *cred = (struct cred *)vmalloc(cred_len);
    struct cred *cred1 = (struct cred *)vmalloc(cred_len);
    memcpy(cred, kvar(init_cred), cred_len);
    memcpy(cred1, kvar(init_cred), cred_len);
    *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset) = cred;
    *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset) = cred;
    asm volatile("msr sp_el0, %0" ::"r"(task));

    // todo:
    unsigned long root_user_ptr = kallsyms_lookup_name("root_user");
    unsigned long init_user_ns_ptr = kallsyms_lookup_name("init_user_ns");
    unsigned long init_groups_ptr = kallsyms_lookup_name("init_groups");
    unsigned long init_ucounts_ptr = kallsyms_lookup_name("init_ucounts");

    for (int16_t i = 0; i < cred_len; i += sizeof(uintptr_t)) {
        uintptr_t ptr = *(uintptr_t *)((uintptr_t)kvar(init_cred) + i);
        if (root_user_ptr && ptr == root_user_ptr) {
            cred_offset.user_offset = i;
            add_bll(i, sizeof(uintptr_t));
        }
        if (init_user_ns_ptr && ptr == init_user_ns_ptr) {
            cred_offset.user_ns_offset = i;
            add_bll(i, sizeof(uintptr_t));
        }
        if (init_groups_ptr && ptr == init_groups_ptr) {
            cred_offset.group_info_offset = i;
            add_bll(i, sizeof(uintptr_t));
        }
        if (init_ucounts_ptr && ptr == init_ucounts_ptr) {
            cred_offset.ucounts_offset = i;
            add_bll(i, sizeof(uintptr_t));
        }
    }
    logkd("struct cred offsets: user: %d, user_ns: %d, group_info: %d\n", cred_offset.user_offset,
          cred_offset.user_ns_offset, cred_offset.group_info_offset);

    for (int16_t i = 0; i < cred_len; i += sizeof(unsigned)) {
        unsigned int val = *(unsigned int *)((uintptr_t)kvar(init_cred) + i);
        if (4 == val) {
            cred_offset.usage_offset = i;
            add_bll(i, sizeof(unsigned));
        }
        if (CRED_MAGIC == val) {
            cred_offset.magic_offset = i;
            add_bll(i, sizeof(unsigned));
        }
        if (2 == val) {
            cred_offset.subscribers_offset = i;
            add_bll(i, sizeof(unsigned));
        }
    }
    logkd("struct cred offsets: usage: %d, magic: %d, subscribers: %d\n", cred_offset.usage_offset,
          cred_offset.magic_offset, cred_offset.subscribers_offset);

    // cap_inheritable, cap_permitted, cap_effective
    kernel_cap_t effective, inheritable, permitted;
    cap_capget(task, &effective, &inheritable, &permitted);
    full_cap.val = effective.val;
    logkd("capability full_cap: %llx\n", full_cap.val);

    kernel_cap_t new_cap_e = { 0xff }, new_cap_i = { 0xf }, new_cap_p = { 0xfff };
    cap_capset(cred1, cred, &new_cap_e, &new_cap_i, &new_cap_p);

    for (int16_t i = 0; i < cred_len; i += sizeof(kernel_cap_t)) {
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
    for (int16_t i = 0; i < cred_len; i += sizeof(kernel_cap_t)) {
        if (is_bl(i)) continue;
        kernel_cap_t cap1 = *(kernel_cap_t *)((uintptr_t)cred1 + i);
        if (cap1.val == effective.val) {
            cred_offset.cap_bset_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
        }
    }
    logkd("struct cred offsets: cap_effective: %d, cap_inheritable: %d, cap_permitted: %d, cap_bset: %d\n",
          cred_offset.cap_effective_offset, cred_offset.cap_inheritable_offset, cred_offset.cap_permitted_offset,
          cred_offset.cap_bset_offset);

    // securebits
    for (int i = 0; i < cred_len; i += sizeof(unsigned)) {
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
    logkd("struct cred offsets: securebits: %d\n", cred_offset.securebits_offset);

    // euid, uid, egid, gid
    for (int i = 0; i < cred_len; i += sizeof(uid_t)) {
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
    logkd("struct cred offsets: uid: %d, euid: %d, gid: %d, egid: %d\n", cred_offset.uid_offset,
          cred_offset.euid_offset, cred_offset.gid_offset, cred_offset.egid_offset);

    // fsuid
    raw_syscall1(__NR_setfsuid, 1158);
    struct cred *new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < cred_len; i += sizeof(uid_t)) {
        if (is_bl(i)) continue;
        uid_t *uidp = (uid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.fsuid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(uid_t));
            break;
        }
    }
    logkd("struct cred offsets: fsuid: %d\n", cred_offset.fsuid_offset);

    // suid
    raw_syscall3(__NR_setresuid, 0, 0, 1158);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < cred_len; i += sizeof(uid_t)) {
        if (is_bl(i)) continue;
        uid_t *uidp = (uid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.suid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(uid_t));
            break;
        }
    }
    logkd("struct cred offsets: suid: %d\n", cred_offset.suid_offset);

    // fsgid
    raw_syscall1(__NR_setfsgid, 1158);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < cred_len; i += sizeof(gid_t)) {
        if (is_bl(i)) continue;
        gid_t *uidp = (gid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.fsgid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(gid_t));
            break;
        }
    }
    logkd("struct cred offsets: fsgid: %d\n", cred_offset.fsgid_offset);

    // sgid
    raw_syscall3(__NR_setresgid, 0, 0, 1158);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < cred_len; i += sizeof(gid_t)) {
        if (is_bl(i)) continue;
        gid_t *uidp = (gid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.sgid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(gid_t));
            break;
        }
    }
    logkd("struct cred offsets: sgid: %d\n", cred_offset.sgid_offset);

    // cap_ambient
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_permitted_offset) = full_cap;
    *(unsigned *)((uintptr_t)new_cred + cred_offset.securebits_offset) = 0;
    cap_task_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 0xf, 0, 0);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int16_t i = 0; i < cred_len; i += sizeof(kernel_cap_t)) {
        if (is_bl(i)) continue;
        kernel_cap_t cap = *(kernel_cap_t *)((uintptr_t)cred + i);
        kernel_cap_t new_cap = *(kernel_cap_t *)((uintptr_t)new_cred + i);
        if (!cap.val && new_cap.val == (1 << 0xf)) {
            cred_offset.cap_ambient_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
        }
    }
    logkd("struct cred offsets: cap_ambient: %d\n", cred_offset.cap_ambient_offset);

    // todo: put new_cred

    asm volatile("msr sp_el0, %0" ::"r"(backup));
    uninit_bllist();

    vfree(task);
    vfree(cred);
    vfree(cred1);
    return 0;
}

int build_task_offset()
{
    int cred_len = kvlen(init_cred);
    int task_len = kvlen(init_task);

    if (task_len <= 0 || cred_len <= 0) {
        logke("init_task or init_cred length unknown\n");
        return -1;
    }

    struct task_struct *task = (struct task_struct *)vmalloc(task_len);
    memcpy(task, kvar(init_task), task_len);

    uintptr_t start = (uintptr_t)task;
    uintptr_t end = start + task_len;
    uintptr_t find = 0;
    int16_t cand[8] = { 0 };
    int ci = 0;

    // find: cred real_cred
    find = (uintptr_t)kvar(init_cred);
    memset(cand, 0, sizeof(cand));
    ci = 0;
    for (uintptr_t i = start; i < end; i += sizeof(uintptr_t)) {
        uintptr_t val = *(uintptr_t *)i;
        if (find == val) { cand[ci++] = i - start; }
    }
    if (ci != 2) return -2;
    //
    struct cred *flag = (struct cred *)vmalloc(cred_len);
    memcpy(flag, kvar(init_cred), cred_len);

    // struct cred *flag = cred_alloc_blank();
    *(uintptr_t *)(start + cand[0]) = (uintptr_t)flag;
    const struct cred *real_cred = get_task_cred(task);
    if (real_cred == flag) {
        task_struct_offset.real_cred_offset = cand[0];
        task_struct_offset.cred_offset = cand[1];
    } else {
        task_struct_offset.real_cred_offset = cand[1];
        task_struct_offset.cred_offset = cand[0];
    }
    vfree(flag);
    logkd("struct task_struct offsets: cred: %d, read_cred: %d\n", task_struct_offset.cred_offset,
          task_struct_offset.real_cred_offset);

    vfree(task);
    return 0;
}

// todo: tid and tgid offsets of task_struct.

int struct_offset_init()
{
    unsigned long offset = 0;
    unsigned long size = 0;
    char mod[16] = { '\0' };
    char name[16] = { '\0' };

    lookup_symbol_attrs((unsigned long)kvar(init_cred), &size, &offset, mod, name);
    kvlen(init_cred) = size;

    lookup_symbol_attrs((unsigned long)kvar(init_task), &size, &offset, mod, name);
    kvlen(init_task) = size;

    return 0;
}