#include "stdio_impl.h"
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "fsclient.h"
#include "eapp.h"
#include "fscallargs.h"
FILE *fopen(const char *restrict filename, const char *restrict mode)
{
	FILE *f;
	unsigned long lfd;
	int fd;
	int flags;

	/* Check for valid initial mode character */
	if (!strchr("rwa", *mode)) {
		errno = EINVAL;
		return 0;
	}
	if(strlen(filename)>=MAXPATH){
		return 0;
	}
	/* Compute the flags to pass to open() */
	flags = __fmodeflags(mode);
	// fd = sys_open(filename, flags, 0666);
	fd = cli_sys_open(filename,flags);
	
	if (fd < 0) return 0;
	if (flags & O_CLOEXEC)
		__syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC);

	f = __fdopen(fd, mode);
	if (f) return f;

	__syscall(SYS_close, fd);
	return 0;
}

weak_alias(fopen, fopen64);
