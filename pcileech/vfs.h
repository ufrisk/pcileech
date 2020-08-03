// vfs.h : definitions related to virtual file system support.
//
// (c) Ulf Frisk, 2017-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VFS_H__
#define __VFS_H__
#include "pcileech.h"
#include "oscompatibility.h"

#define VFS_FLAGS_FILE_NORMAL           0x01
#define VFS_FLAGS_FILE_DIRECTORY        0x02
#define VFS_FLAGS_FILE_SYMLINK          0x04
#define VFS_FLAGS_FILE_OTHER            0x08
#define VFS_FLAGS_UNICODE               0x10
#define VFS_FLAGS_EXIST_FILE            0x20
#define VFS_FLAGS_TRUNCATE_ON_WRITE     0x40
#define VFS_FLAGS_APPEND_ON_WRITE       0x80

typedef struct tdVFS_RESULT_FILEINFO {
    QWORD flags;
    QWORD tAccessOpt;
    QWORD tModifyOpt;
    QWORD tCreateOpt;
    QWORD dbg1;
    QWORD dbg2;
    QWORD cb;
    WCHAR wszFileName[MAX_PATH];
} VFS_RESULT_FILEINFO, *PVFS_RESULT_FILEINFO;

/*
* Mount a drive backed by PCILeech virtual file system. The mounted file system
* will contain both a memory mapped ram files and the file system as seen from
* the target system kernel. NB! This action requires a loaded kernel module and
* that the Dokany file system library and driver have been installed. Please
* see: https://github.com/dokan-dev/dokany/releases
* -- pDeviceData
*/
VOID ActionMount();

#endif /* __VFS_H__ */
