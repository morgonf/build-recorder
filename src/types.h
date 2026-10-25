
/*
Copyright (C) 2022 Alexios Zavras
Copyright (C) 2022 Valasiadis Fotios
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/ptrace.h>

/*
 * For each file, we keep its name/path
 * (the argument to the open(2) call that opened it,
 * whether it was opened for reading or for writing
 * (re-using the O_ flags),
 * and a hash of the contents.
 * Not all info is added at the same time.
 */
typedef struct {
    char *path;
    char *abspath;
    char *hash;
    char outname[16];
} FILE_INFO;

/*
 * For each (sub-)process we keep its pid,
 * the list of files that are currently open for writing,
 * and, while it's running, its current syscall number
 * and arguments.
 */
/*
 * A static archive's members, parsed once per content node: a node's outname
 * stands for its bytes, so the same outname is the same member table.  A
 * member's own node is written the first time a process is seen loading it.
 */
typedef struct {
    char *name;
    int64_t start;		       // first byte of the member's data
    int64_t size;
    char outname[16];		       // "" until the member's node is written
    char lastp[16];		       // last process recorded as loading it
} AR_MEMBER;

typedef struct {
    char foutname[16];
    char *abspath;
    AR_MEMBER *m;
    int nm;
} AR_INFO;

/*
 * A descriptor open on a static archive.  dup(2) copies share one file
 * offset, as the kernel's do, so the position lives in a shared record.
 */
typedef struct {
    int64_t pos;
    int refs;
} AR_OFD;

typedef struct {
    int fd;
    int ar;			       // index into the archive table
    AR_OFD *ofd;
} AR_FD;

typedef struct {
    char outname[16];
    int *fds;
    FILE_INFO *finfo;
    int numfinfo;
    int finfo_size;
    uint64_t nr;
    uint64_t args[6];
    void *entry_info;
    char ignore_one_sigstop;
    char declared;		       // `a b:process' already written out
    char is_thread;		       // shares its subject with the group leader
    pid_t tgid;			       // its group leader, when is_thread
    unsigned int coverage_gaps;
    AR_FD *arfds;		       // descriptors open on static archives
    int narfds;
    int arfds_size;
    char lto_plugin;		       // this image loaded gcc's LTO plugin
} PROCESS_INFO;

/*
 * Bits of PROCESS_INFO.coverage_gaps: mechanisms this process used that can
 * move file content past syscall observation. Recorded per process (once per
 * kind) so the analysis layer can refuse to claim GREEN on a trace whose
 * file layer is not, in fact, complete.
 */
#define	GAP_IO_URING	0x1u
