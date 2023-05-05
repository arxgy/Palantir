#include <unistd.h>
#include <fcntl.h>
#include "syscall.h"
#include "eapp.h"
#include "fscallargs.h"
#include "fsclient.h"
#include <string.h>
int unlink(const char *path)
{
	void *buf = get_pre_mapped_page();
	struct unlink_arg *unlink_arg = (struct unlink_arg*)buf;
	strcpy(unlink_arg->path,path);
	struct call_enclave_arg_t call_arg;
	call_arg.req_vaddr = (unsigned long)buf;
	call_arg.req_size = PRE_MAP_SIZE;
	call_arg.req_arg = UNLINK;
	int status = call_enclave(get_fs_handle(),&call_arg);
	set_pre_map_page(call_arg.req_vaddr);
	if(status){
		return -1;
	}
	return call_arg.resp_val;
// #ifdef SYS_unlink
// 	return syscall(SYS_unlink, path);
// #else
// 	return syscall(SYS_unlinkat, AT_FDCWD, path, 0);
// #endif
}
