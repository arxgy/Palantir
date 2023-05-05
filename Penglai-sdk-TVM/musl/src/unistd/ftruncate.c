#include <unistd.h>
#include "syscall.h"
#include "print.h"
#include "fsclient.h"
#include "fscallargs.h"
#include "eapp.h"
int ftruncate(int fd, off_t length)
{
	if(length != 0){
		eapp_print("ftruncate only support truncate to 0 now\n");
		return -1;
	}
	void *buf = get_pre_mapped_page();
	struct ftruncate_arg *truncate_arg = (struct ftruncate_arg*)buf;
	truncate_arg->fd = fd;
	struct call_enclave_arg_t call_arg;
	call_arg.req_arg = FTRUNCATE;
	call_arg.req_vaddr = (unsigned long)buf;
	call_arg.req_size = PRE_MAP_SIZE;
	int status = call_enclave(get_fs_handle(),&call_arg);
	set_pre_map_page(call_arg.req_vaddr);
	if(status){
		return -1;	
	}
	return call_arg.resp_val;
	// return syscall(SYS_ftruncate, fd, __SYSCALL_LL_O(length));
}

weak_alias(ftruncate, ftruncate64);
