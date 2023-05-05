#define _BSD_SOURCE
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include "syscall.h"
#include "fscallargs.h"
#include "fsclient.h"
// FIXME: only support stat file length at this time
int fstat(int fd, struct stat *st)
{
#if 0
	if (fd<0) return __syscall_ret(-EBADF);
	return fstatat(fd, "", st, AT_EMPTY_PATH);
#endif
	return penglai_fstat(fd,0,st);

}

#if !_REDIR_TIME64
weak_alias(fstat, fstat64);
#endif
