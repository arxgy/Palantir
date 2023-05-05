#include <unistd.h>
#include <errno.h>
#include "syscall.h"
#include "fsclient.h"
#include "eapp.h"
#include "fscallargs.h"
static int dummy(int fd)
{
	return fd;
}

weak_alias(dummy, __aio_close);

int close(int fd)
{
	fd = __aio_close(fd);
	// int r = __syscall_cp(SYS_close, fd);
	void *buf = get_pre_mapped_page();
	((struct close_arg*)buf)->fd = fd;
	struct call_enclave_arg_t call_arg;
	call_arg.req_arg = FSCLOSE;
	call_arg.req_vaddr = (unsigned long)buf;
	call_arg.req_size = PRE_MAP_SIZE;
	int status = call_enclave(get_fs_handle(),&call_arg);
	set_pre_map_page(call_arg.req_vaddr);
	// int r = sys_close(fd);
	int r = (int)call_arg.resp_val;
	if (r == -EINTR) r = 0;
	// return __syscall_ret(r);
	return r;
}
