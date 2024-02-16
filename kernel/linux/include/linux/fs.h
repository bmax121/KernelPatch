#ifndef _LINUX_FS_H
#define _LINUX_FS_H

#include <ktypes.h>
#include <ksyms.h>
#include <common.h>
#include <uapi/asm-generic/fcntl.h>
#include <uapi/linux/fs.h>

#define MAY_EXEC 0x00000001
#define MAY_WRITE 0x00000002
#define MAY_READ 0x00000004
#define MAY_APPEND 0x00000008
#define MAY_ACCESS 0x00000010
#define MAY_OPEN 0x00000020
#define MAY_CHDIR 0x00000040
/* called from RCU mode, don't block */
#define MAY_NOT_BLOCK 0x00000080

/*
 * flags in file.f_mode.  Note that FMODE_READ and FMODE_WRITE must correspond
 * to O_WRONLY and O_RDWR via the strange trick in do_dentry_open()
 */

/* file is open for reading */
#define FMODE_READ ((__force fmode_t)0x1)
/* file is open for writing */
#define FMODE_WRITE ((__force fmode_t)0x2)
/* file is seekable */
#define FMODE_LSEEK ((__force fmode_t)0x4)
/* file can be accessed using pread */
#define FMODE_PREAD ((__force fmode_t)0x8)
/* file can be accessed using pwrite */
#define FMODE_PWRITE ((__force fmode_t)0x10)
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC ((__force fmode_t)0x20)
/* File is opened with O_NDELAY (only set for block devices) */
#define FMODE_NDELAY ((__force fmode_t)0x40)
/* File is opened with O_EXCL (only set for block devices) */
#define FMODE_EXCL ((__force fmode_t)0x80)
/* File is opened using open(.., 3, ..) and is writeable only for ioctls
   (specialy hack for floppy.c) */
#define FMODE_WRITE_IOCTL ((__force fmode_t)0x100)
/* 32bit hashes as llseek() offset (for directories) */
#define FMODE_32BITHASH ((__force fmode_t)0x200)
/* 64bit hashes as llseek() offset (for directories) */
#define FMODE_64BITHASH ((__force fmode_t)0x400)

/*
 * Don't update ctime and mtime.
 *
 * Currently a special hack for the XFS open_by_handle ioctl, but we'll
 * hopefully graduate it to a proper O_CMTIME flag supported by open(2) soon.
 */
#define FMODE_NOCMTIME ((__force fmode_t)0x800)

/* Expect random access pattern */
#define FMODE_RANDOM ((__force fmode_t)0x1000)

/* File is huge (eg. /dev/kmem): treat loff_t as unsigned */
#define FMODE_UNSIGNED_OFFSET ((__force fmode_t)0x2000)

/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH ((__force fmode_t)0x4000)

/* File needs atomic accesses to f_pos */
#define FMODE_ATOMIC_POS ((__force fmode_t)0x8000)
/* Write access to underlying fs */
#define FMODE_WRITER ((__force fmode_t)0x10000)
/* Has read method(s) */
#define FMODE_CAN_READ ((__force fmode_t)0x20000)
/* Has write method(s) */
#define FMODE_CAN_WRITE ((__force fmode_t)0x40000)

/* File was opened by fanotify and shouldn't generate fanotify events */
#define FMODE_NONOTIFY ((__force fmode_t)0x1000000)

/*
 * Flag for rw_copy_check_uvector and compat_rw_copy_check_uvector
 * that indicates that they should check the contents of the iovec are
 * valid, but not check the memory that the iovec elements
 * points too.
 */
#define CHECK_IOVEC_ONLY -1

#define RW_MASK REQ_WRITE
#define RWA_MASK REQ_RAHEAD

#define READ 0
#define WRITE RW_MASK
#define READA RWA_MASK

#define READ_SYNC (READ | REQ_SYNC)
#define WRITE_SYNC (WRITE | REQ_SYNC | REQ_NOIDLE)
#define WRITE_ODIRECT (WRITE | REQ_SYNC)
#define WRITE_FLUSH (WRITE | REQ_SYNC | REQ_NOIDLE | REQ_FLUSH)
#define WRITE_FUA (WRITE | REQ_SYNC | REQ_NOIDLE | REQ_FUA)
#define WRITE_FLUSH_FUA (WRITE | REQ_SYNC | REQ_NOIDLE | REQ_FLUSH | REQ_FUA)

/*
 * Attribute flags.  These should be or-ed together to figure out what
 * has been changed!
 */
#define ATTR_MODE (1 << 0)
#define ATTR_UID (1 << 1)
#define ATTR_GID (1 << 2)
#define ATTR_SIZE (1 << 3)
#define ATTR_ATIME (1 << 4)
#define ATTR_MTIME (1 << 5)
#define ATTR_CTIME (1 << 6)
#define ATTR_ATIME_SET (1 << 7)
#define ATTR_MTIME_SET (1 << 8)
#define ATTR_FORCE (1 << 9) /* Not a change, but a change it */
#define ATTR_ATTR_FLAG (1 << 10)
#define ATTR_KILL_SUID (1 << 11)
#define ATTR_KILL_SGID (1 << 12)
#define ATTR_FILE (1 << 13)
#define ATTR_KILL_PRIV (1 << 14)
#define ATTR_OPEN (1 << 15) /* Truncating from open(O_TRUNC) */
#define ATTR_TIMES_SET (1 << 16)

/*
 * Whiteout is represented by a char device.  The following constants define the
 * mode and device number to use.
 */
#define WHITEOUT_MODE 0
#define WHITEOUT_DEV 0

/* fs/open.c */
struct audit_names;
struct filename
{
    const char *name; /* pointer to actual string */
    const __user char *uptr; /* original userland pointer */
    struct audit_names *aname;
    int refcnt;
    const char iname[];
};

/*
 * Inode flags - they have no relation to superblock flags now
 */
#define S_SYNC 1 /* Writes are synced at once */
#define S_NOATIME 2 /* Do not update access times */
#define S_APPEND 4 /* Append-only file */
#define S_IMMUTABLE 8 /* Immutable file */
#define S_DEAD 16 /* removed, but still open directory */
#define S_NOQUOTA 32 /* Inode is not counted to quota */
#define S_DIRSYNC 64 /* Directory modifications are synchronous */
#define S_NOCMTIME 128 /* Do not update file c/mtime */
#define S_SWAPFILE 256 /* Do not truncate: swapon got its bmaps */
#define S_PRIVATE 512 /* Inode is fs-internal */
#define S_IMA 1024 /* Inode has an associated IMA struct */
#define S_AUTOMOUNT 2048 /* Automount/referral quasi-directory */
#define S_NOSEC 4096 /* no suid or xattr security attributes */

#define __IS_FLG(inode, flg) ((inode)->i_sb->s_flags & (flg))

#define IS_RDONLY(inode) ((inode)->i_sb->s_flags & MS_RDONLY)
#define IS_SYNC(inode) (__IS_FLG(inode, MS_SYNCHRONOUS) || ((inode)->i_flags & S_SYNC))
#define IS_DIRSYNC(inode) (__IS_FLG(inode, MS_SYNCHRONOUS | MS_DIRSYNC) || ((inode)->i_flags & (S_SYNC | S_DIRSYNC)))
#define IS_MANDLOCK(inode) __IS_FLG(inode, MS_MANDLOCK)
#define IS_NOATIME(inode) __IS_FLG(inode, MS_RDONLY | MS_NOATIME)
#define IS_I_VERSION(inode) __IS_FLG(inode, MS_I_VERSION)

#define IS_NOQUOTA(inode) ((inode)->i_flags & S_NOQUOTA)
#define IS_APPEND(inode) ((inode)->i_flags & S_APPEND)
#define IS_IMMUTABLE(inode) ((inode)->i_flags & S_IMMUTABLE)
#define IS_POSIXACL(inode) __IS_FLG(inode, MS_POSIXACL)

#define IS_DEADDIR(inode) ((inode)->i_flags & S_DEAD)
#define IS_NOCMTIME(inode) ((inode)->i_flags & S_NOCMTIME)
#define IS_SWAPFILE(inode) ((inode)->i_flags & S_SWAPFILE)
#define IS_PRIVATE(inode) ((inode)->i_flags & S_PRIVATE)
#define IS_IMA(inode) ((inode)->i_flags & S_IMA)
#define IS_AUTOMOUNT(inode) ((inode)->i_flags & S_AUTOMOUNT)
#define IS_NOSEC(inode) ((inode)->i_flags & S_NOSEC)

#define IS_WHITEOUT(inode) (S_ISCHR(inode->i_mode) && (inode)->i_rdev == WHITEOUT_DEV)

#define I_DIRTY_SYNC (1 << 0)
#define I_DIRTY_DATASYNC (1 << 1)
#define I_DIRTY_PAGES (1 << 2)
#define __I_NEW 3
#define I_NEW (1 << __I_NEW)
#define I_WILL_FREE (1 << 4)
#define I_FREEING (1 << 5)
#define I_CLEAR (1 << 6)
#define __I_SYNC 7
#define I_SYNC (1 << __I_SYNC)
#define I_REFERENCED (1 << 8)
#define __I_DIO_WAKEUP 9
#define I_DIO_WAKEUP (1 << I_DIO_WAKEUP)
#define I_LINKABLE (1 << 10)

#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)

#define FL_POSIX 1
#define FL_FLOCK 2
#define FL_DELEG 4 /* NFSv4 delegation */
#define FL_ACCESS 8 /* not trying to lock, just looking */
#define FL_EXISTS 16 /* when unlocking, test for existence */
#define FL_LEASE 32 /* lease held on this file */
#define FL_CLOSE 64 /* unlock on close */
#define FL_SLEEP 128 /* A blocking lock */
#define FL_DOWNGRADE_PENDING 256 /* Lease is being downgraded */
#define FL_UNLOCK_PENDING 512 /* Lease is being broken */
#define FL_OFDLCK 1024 /* lock is "owned" by struct file */

/*
 * Special return value from posix_lock_file() and vfs_lock_file() for
 * asynchronous locking.
 */
#define FILE_LOCK_DEFERRED 1

/* legacy typedef, should eventually be removed */
typedef void *fl_owner_t;
struct cred;
struct vfsmount;
struct file;
struct path;
struct dentry;
struct inode;

extern void kfunc_def(inc_nlink)(struct inode *inode);
extern void kfunc_def(drop_nlink)(struct inode *inode);
extern void kfunc_def(clear_nlink)(struct inode *inode);
extern void kfunc_def(set_nlink)(struct inode *inode, unsigned int nlink);

extern ssize_t kfunc_def(kernel_read)(struct file *file, void *buf, size_t count, loff_t *pos);
extern ssize_t kfunc_def(kernel_write)(struct file *file, const void *buf, size_t count, loff_t *pos);
extern ssize_t kfunc_def(__kernel_write)(struct file *, const char *, size_t, loff_t *);
extern struct file *kfunc_def(open_exec)(const char *);

extern struct file *kfunc_def(file_open_name)(struct filename *, int, umode_t);
extern struct file *kfunc_def(filp_open)(const char *, int, umode_t);
extern struct file *kfunc_def(file_open_root)(struct dentry *, struct vfsmount *, const char *, int, umode_t);
extern struct file *kfunc_def(dentry_open)(const struct path *, int, const struct cred *);
extern int kfunc_def(filp_close)(struct file *, fl_owner_t id);

extern struct filename *kfunc_def(getname)(const char __user *);
extern struct filename *kfunc_def(getname_kernel)(const char *);
extern void kfunc_def(putname)(struct filename *name);
extern void kfunc_def(final_putname)(struct filename *name);

extern loff_t kfunc_def(vfs_llseek)(struct file *file, loff_t offset, int whence);

//

static inline void inc_nlink(struct inode *inode)
{
    kfunc_call_void(inc_nlink, inode);
}

static inline void drop_nlink(struct inode *inode)
{
    kfunc_call_void(drop_nlink, inode);
}

static inline void clear_nlink(struct inode *inode)
{
    kfunc_call_void(clear_nlink, inode);
}

static inline void set_nlink(struct inode *inode, unsigned int nlink)
{
    kfunc_call_void(set_nlink, inode, nlink);
}

static inline ssize_t kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
    ssize_t ret = 0;
    if (kfunc(kernel_read)) {
        if (kver < VERSION(4, 14, 0)) {
            loff_t offset = pos ? *pos : 0;
            int (*kernel_read_legacy)(struct file *file, loff_t offset, char *addr, unsigned long count) =
                (typeof(kernel_read_legacy))kfunc(kernel_read);
            int rc = kernel_read_legacy(file, offset, (char *)buf, count);
            if (pos && rc > 0) {
                *pos = offset + rc;
            }
            ret = rc;
        } else {
            ret = kfunc(kernel_read)(file, buf, count, pos);
        }
    } else {
        kfunc_not_found();
    }
    return ret;
}

static inline ssize_t kernel_write(struct file *file, const void *buf, size_t count, loff_t *pos)
{
    ssize_t ret = 0;
    if (kfunc(kernel_write)) {
        if (kver < VERSION(4, 14, 0)) {
            ssize_t (*kernel_write_legacy)(struct file *file, const char *buf, size_t count, loff_t pos) =
                (typeof(kernel_write_legacy))kfunc(kernel_write);
            loff_t offset = pos ? *pos : 0;
            ssize_t result = kernel_write_legacy(file, buf, count, offset);
            if (pos && result > 0) {
                *pos = offset + result;
            }
            ret = result;
        } else {
            kfunc(kernel_write)(file, buf, count, pos);
        }
    } else {
        kfunc_not_found();
    }
    return ret;
}

static inline struct file *open_exec(const char *name)
{
    kfunc_direct_call(open_exec, name);
}

static inline struct file *file_open_name(struct filename *name, int flags, umode_t mode)
{
    kfunc_direct_call(file_open_name, name, flags, mode);
}

static inline struct file *filp_open(const char *filename, int flags, umode_t mode)
{
    kfunc_direct_call(filp_open, filename, flags, mode);
}

static inline struct file *file_open_root(struct dentry *dentry, struct vfsmount *mnt, const char *filename, int flags,
                                          umode_t mode)
{
    kfunc_direct_call(file_open_root, dentry, mnt, filename, flags, mode);
}

static inline struct file *dentry_open(const struct path *path, int flags, const struct cred *cred)
{
    kfunc_direct_call(dentry_open, path, flags, cred);
}

static inline int filp_close(struct file *filp, fl_owner_t id)
{
    kfunc_direct_call(filp_close, filp, id);
}

static inline struct filename *getname(const char __user *filename)
{
    kfunc_direct_call(getname, filename);
}

static inline struct filename *getname_kernel(const char *filename)
{
    kfunc_direct_call(getname_kernel, filename);
}

static inline loff_t vfs_llseek(struct file *file, loff_t offset, int whence)
{
    kfunc_direct_call(vfs_llseek, file, offset, whence);
}

static inline void putname(struct filename *name)
{
    // logkd("aaaaaaaaaaa %llx\n", kfunc(putname));
    kfunc_direct_call_void(putname, name);
    // kfunc_direct_call_void(final_putname, name);
}

#endif