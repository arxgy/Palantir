#include <unistd.h>
#include "syscall.h"
#include "fscallargs.h"
#include "eapp.h"
#include "fsclient.h"
off_t __lseek(int fd, off_t offset, int whence)
{
	struct lseek_arg *lseek_arg = (struct lseek_arg*)(get_pre_mapped_page());
	lseek_arg->fd = fd;
	lseek_arg->offset = offset;
	lseek_arg->whence = whence;
	struct call_enclave_arg_t call_arg;
	call_arg.req_arg = FSLSEEK;
	call_arg.req_vaddr = (unsigned long)lseek_arg;
	call_arg.req_size = PRE_MAP_SIZE;
	int status = call_enclave(get_fs_handle(),&call_arg);
	set_pre_map_page(call_arg.req_vaddr);
	if(status){
		return -1;
	}
	else{
		return (off_t)(call_arg.resp_val);
	}

}

weak_alias(__lseek, lseek);
weak_alias(__lseek, lseek64);
