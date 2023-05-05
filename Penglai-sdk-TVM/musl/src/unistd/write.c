#include <unistd.h>
#include "syscall.h"
#include "fsclient.h"
#include "eapp.h"
#include "fscallargs.h"
#include<string.h>
#include "print.h"
ssize_t write(int fd, const void *buf, size_t count)
{
	// return syscall_cp(SYS_write, fd, buf, count);
	// return sys_write(fd,buf,count);
	void* transfer_buf;
	size_t transfer_size;
	ssize_t ret;
	int new_map = 0;
	if(count > PRE_MAP_SIZE - sizeof(struct write_arg)){
		transfer_size = ((count + sizeof(struct write_arg))/PRE_MAP_SIZE+1)*PRE_MAP_SIZE;
		transfer_buf = eapp_mmap(0,transfer_size);
		new_map = 1;
	}
	else{
		transfer_size = PRE_MAP_SIZE;
		transfer_buf = get_pre_mapped_page();
	}
	struct write_arg *write_arg = (struct write_arg*)transfer_buf;
	write_arg->fd = fd;
	write_arg->size = count;
	memcpy((char*)transfer_buf + sizeof(struct write_arg),buf,count);
	struct call_enclave_arg_t call_arg;
	call_arg.req_vaddr = (unsigned long)transfer_buf;
	call_arg.req_size = transfer_size;
	call_arg.req_arg = FSWRITE;
	int status = call_enclave(get_fs_handle(),&call_arg);
	if(!new_map){
		set_pre_map_page(call_arg.req_vaddr);
	}	
	transfer_buf = (void *)call_arg.req_vaddr;
	ret = (ssize_t)call_arg.resp_val;
	if(status){
		ret = -1;
	}
	if(new_map){
		eapp_unmap(transfer_buf,transfer_size);
	}
	return ret;
}
