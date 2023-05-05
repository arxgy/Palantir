#include <sys/stat.h>
#include <fcntl.h>
#include "syscall.h"
#include "eapp.h"
#include "fscallargs.h"
#include "fsclient.h"
#include <string.h>
int mkdir(const char *path, mode_t mode)
{
#if 0
#ifdef SYS_mkdir
	return syscall(SYS_mkdir, path, mode);
#else
	return syscall(SYS_mkdirat, AT_FDCWD, path, mode);
#endif
#endif
	struct mkdir_arg* mkdir_arg = (struct mkdir_arg*)get_pre_mapped_page();
	strcpy(mkdir_arg->path, path);
	struct call_enclave_arg_t call_arg;
	call_arg.req_arg = FSMKDIR;
	call_arg.req_vaddr = mkdir_arg;
	call_arg.req_size = PRE_MAP_SIZE;
	int status = call_enclave(get_fs_handle(), &call_arg);
	set_pre_map_page(call_arg.req_vaddr);
	if(status){
		return -1;
	}
	else{
		return call_arg.resp_val;
	}
}
