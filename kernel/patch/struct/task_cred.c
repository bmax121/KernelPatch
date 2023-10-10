#include <log.h>
#include <stdbool.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <asm/current.h>
#include <linux/security.h>
#include <syscall.h>
#include <uapi/linux/prctl.h>
#include <linux/capability.h>
#include <ksyms.h>
#include <uapi/linux/magic.h>
#include <pgtable.h>
#include <error.h>

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
    .stack_offset = -1,
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

int thread_size = -1;
bool thread_info_in_task = false;
bool task_is_sp_el0 = false;
bool thread_info_is_sp_el0 = false;
bool thread_info_is_sp = false;
int task_in_thread_info_offset = -1;
int stack_in_task_offset = -1;
int stack_end_offset = 0x90;
int thread_info_size = 0x90;

struct task_struct *task = 0;

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
    vfree(bl_list);
    bl_cap = 0;
}

static bool is_bl(int16_t off)
{
    for (int i = 0; i < bl_cap; i++) {
        if (bl_list[i] < 0)
            break;
        if (bl_list[i] == off)
            return true;
    }
    return false;
}

static void add_bll(int16_t off, int16_t size)
{
    for (int i = 0; i < bl_cap; i++) {
        if (bl_list[i] < 0) {
            bl_list[i] = off;
            if (size == 8)
                bl_list[i + 1] = off + 4;
            break;
        }
    }
}

// todo:
int build_cred_offset()
{
    int cred_len = kvlen(init_cred);
    int task_len = kvlen(init_task);

    logkd("struct cred: \n");

    if (task_len <= 0 || cred_len <= 0) {
        logke("init_task or init_cred length unknown\n");
        return -1;
    }
    reinit_bllist(128);

    struct cred *cred = cred_alloc_blank();
    struct cred *cred1 = cred_alloc_blank();

    memcpy(task, kvar(init_task), task_len);
    memcpy(cred, kvar(init_cred), cred_len);
    memcpy(cred1, kvar(init_cred), cred_len);
    *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset) = cred;
    *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset) = cred;

    const struct task_struct *backup = override_current(task);

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
    logkd("    user offset: %d\n", cred_offset.user_offset);
    logkd("    user_ns offset: %d\n", cred_offset.user_ns_offset);
    logkd("    group_info offset: %d\n", cred_offset.group_info_offset);

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
    logkd("    usage offset: %d\n", cred_offset.usage_offset);

    // cap_inheritable, cap_permitted, cap_effective
    kernel_cap_t effective, inheritable, permitted;
    cap_capget(task, &effective, &inheritable, &permitted);
    full_cap.val = effective.val;
    logkd("    full_cap capability: %llx\n", full_cap.val);

    kernel_cap_t new_cap_e = { 0xff }, new_cap_i = { 0xf }, new_cap_p = { 0xfff };
    cap_capset(cred1, cred, &new_cap_e, &new_cap_i, &new_cap_p);

    for (int16_t i = 0; i < cred_len; i += sizeof(kernel_cap_t)) {
        if (is_bl(i))
            continue;
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
        if (is_bl(i))
            continue;
        kernel_cap_t cap1 = *(kernel_cap_t *)((uintptr_t)cred1 + i);
        if (cap1.val == effective.val) {
            cred_offset.cap_bset_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
        }
    }
    logkd("    cap_effective offset: %d\n", cred_offset.cap_effective_offset);
    logkd("    cap_inheritable offset: %d\n", cred_offset.cap_inheritable_offset);
    logkd("    cap_permitted offset: %d\n", cred_offset.cap_permitted_offset);
    logkd("    cap_bset offset: %d\n", cred_offset.cap_bset_offset);

    // securebits
    for (int i = 0; i < cred_len; i += sizeof(unsigned)) {
        if (is_bl(i))
            continue;
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
    logkd("    securebits offset: %d\n", cred_offset.securebits_offset);

    // euid, uid, egid, gid
    for (int i = 0; i < cred_len; i += sizeof(uid_t)) {
        if (is_bl(i))
            continue;
        uid_t *uidp = (uid_t *)((uintptr_t)cred + i);
        if (*uidp)
            continue;
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
    logkd("    uid offset: %d\n", cred_offset.uid_offset);
    logkd("    euid offset: %d\n", cred_offset.euid_offset);
    logkd("    gid offset: %d\n", cred_offset.gid_offset);
    logkd("    egid offset: %d\n", cred_offset.egid_offset);

    // fsuid
    for (int i = 0; i < cred_len; i += sizeof(uid_t)) {
        if (is_bl(i))
            continue;
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
    logkd("    fsuid offset: %d\n", cred_offset.fsuid_offset);

    // fsgid
    struct cred *new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < cred_len; i += sizeof(gid_t)) {
        if (is_bl(i))
            continue;
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
    logkd("    fsgid offset: %d\n", cred_offset.fsgid_offset);

    // suid
    raw_syscall3(__NR_setresuid, 0, 0, 1158);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < cred_len; i += sizeof(uid_t)) {
        if (is_bl(i))
            continue;
        uid_t *uidp = (uid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.suid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(uid_t));
            break;
        }
    }
    logkd("    suid offset: %d\n", cred_offset.suid_offset);

    // sgid
    raw_syscall3(__NR_setresgid, 0, 0, 1158);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < cred_len; i += sizeof(gid_t)) {
        if (is_bl(i))
            continue;
        gid_t *uidp = (gid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.sgid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(gid_t));
            break;
        }
    }
    logkd("    sgid offset: %d\n", cred_offset.sgid_offset);

    // cap_ambient
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_permitted_offset) = full_cap;
    *(unsigned *)((uintptr_t)new_cred + cred_offset.securebits_offset) = 0;
    cap_task_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 0xf, 0, 0);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int16_t i = 0; i < cred_len; i += sizeof(kernel_cap_t)) {
        if (is_bl(i))
            continue;
        kernel_cap_t cap = *(kernel_cap_t *)((uintptr_t)cred + i);
        kernel_cap_t new_cap = *(kernel_cap_t *)((uintptr_t)new_cred + i);
        if (!cap.val && new_cap.val == (1 << 0xf)) {
            cred_offset.cap_ambient_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
        }
    }
    logkd("    cap_ambient offset: %d\n", cred_offset.cap_ambient_offset);

    // todo: put cred
    // __put_cred(new_cred);

    revert_current(backup);
    uninit_bllist();
    return 0;
}

int build_task_offset()
{
    logkd("struct task: \n");
    int cred_len = kvlen(init_cred);
    int task_len = kvlen(init_task);

    memcpy(task, kvar(init_task), task_len);

    uintptr_t start = (uintptr_t)task;
    uintptr_t end = start + task_len;
    uintptr_t find = 0;
    int16_t cand[8] = { 0 };
    int ci = 0;

    // cred and real_cred
    find = (uintptr_t)kvar(init_cred);
    memset(cand, 0, sizeof(cand));
    ci = 0;
    for (uintptr_t i = start; i < end; i += sizeof(uintptr_t)) {
        uintptr_t val = *(uintptr_t *)i;
        if (find == val) {
            cand[ci++] = i - start;
        }
    }
    if (ci != 2)
        return ERR_STRUCT_LAYOUT;
    //
    struct cred *flag = (struct cred *)vmalloc(kvlen(init_cred));
    memcpy(flag, kvar(init_cred), cred_len);

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

    logkd("    cred offset: %d\n", task_struct_offset.cred_offset);
    logkd("    read_cred offset: %d\n", task_struct_offset.real_cred_offset);

    // stack
    uintptr_t stack_base = (uintptr_t)kvar(init_thread_union);
    for (uintptr_t i = start; i < end; i += sizeof(uintptr_t)) {
        uintptr_t val = *(uintptr_t *)i;
        if (stack_base == val) {
            stack_in_task_offset = i - start;
            task_struct_offset.stack_offset = stack_in_task_offset;
            break;
        }
    }
    logkd("    stack offset: %d\n", task_struct_offset.stack_offset);

    return 0;
}

int resolve_current()
{
    logkd("current: \n");

    int err = 0;
    uintptr_t sp_el0;
    asm("mrs %0, sp_el0" : "=r"(sp_el0));
    uint64_t init_thread_union_addr = (uint64_t)kvar(init_thread_union);

    thread_info_in_task = true;

    for (int i = 0; i < stack_end_offset; i += 8) {
        uint64_t addr = init_thread_union_addr + i;
        uint64_t val = *(uint64_t *)addr;
        if (i > 0) {
            thread_info_in_task = false;
        }
        if (val == STACK_END_MAGIC) {
            stack_end_offset = i + 8;
            break;
        }
    }
    logkd("    stack end offset stack: %d\n", stack_end_offset);
    logkd("    thread_info_in_task: %d\n", thread_info_in_task);

    // where is task
    if (sp_el0 == (uint64_t)kvar(init_task)) {
        task_is_sp_el0 = true;
        logkd("    current is sp_el0\n");
    } else {
        if (sp_el0 == init_thread_union_addr) {
            thread_info_is_sp_el0 = true;
            logkd("    current_thread_info is sp_el0\n");
        } else {
            thread_info_is_sp = true;
            logkd("    current_thread_info is sp\n");
        }

        // task_in_thread_info_offset
        for (int i = 0; i < thread_info_size; i += sizeof(uint64_t)) {
            struct thread_info *thread_info = current_thread_info();
            uint64_t ptr = (uint64_t)thread_info + i;
            if (*(uint64_t *)ptr == (uint64_t)kvar(init_task)) {
                task_in_thread_info_offset = i;
                break;
            }
        }
        logkd("    task offset of thread_info: %d\n", task_in_thread_info_offset);
    }

    return err;
}

int build_struct()
{
    if (kvlen(init_task) <= 0 || kvlen(init_cred) <= 0) {
        logke("init_task or init_cred length unknown\n");
        return ERR_STRUCT_LAYOUT;
    }
    if (thread_size <= 0) {
        thread_size = 16384;
    }

    full_cap = CAP_FULL_SET;
    task = (struct task_struct *)vmalloc(kvlen(init_task));

    int err = 0;
    if ((err = build_task_offset()))
        goto out;
    if ((err = resolve_current()))
        goto out;
    if ((err = build_cred_offset()))
        goto out;

out:
    vfree(task);
    return err;
}