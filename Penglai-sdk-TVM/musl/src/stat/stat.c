#include <sys/stat.h>
#include <fcntl.h>
#include "fsclient.h"
int stat(const char *restrict path, struct stat *restrict buf)
{
#if 0
	return fstatat(AT_FDCWD, path, buf, 0);
#endif
	return penglai_fstat(-1,path,buf);
}

#if !_REDIR_TIME64
weak_alias(stat, stat64);
#endif
