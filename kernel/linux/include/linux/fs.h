#ifndef _LINUX_FS_H
#define _LINUX_FS_H

#include <ktypes.h>

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

// todo:

#endif