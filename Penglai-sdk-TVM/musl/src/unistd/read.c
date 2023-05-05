#include <unistd.h>
#include<string.h>
#include "syscall.h"
#include "fsclient.h"
#include "eapp.h"
#include "fscallargs.h"
ssize_t read(int fd, void *buf, size_t count)
{	
	void *transfer_buf;
	int mapped = 0;
	unsigned long transfer_size;
	if(count > PRE_MAP_SIZE){
		transfer_size = ((count/PRE_MAP_SIZE)+1)*PRE_MAP_SIZE;
		transfer_buf = eapp_mmap(0, transfer_size);
		mapped = 1;
	}
	else{
		transfer_buf = get_pre_mapped_page();
		transfer_size = PRE_MAP_SIZE;
	}
	struct read_arg *read_arg = (struct read_arg*)transfer_buf;
	read_arg->fd = fd;
	read_arg->size = count;
	struct call_enclave_arg_t call_arg;
	call_arg.req_arg = FSREAD;
	call_arg.req_vaddr = (unsigned long)read_arg;
	call_arg.req_size = transfer_size;
	int status = call_enclave(get_fs_handle(),&call_arg);
	if(!mapped){
		set_pre_map_page(call_arg.req_vaddr);
	}
	transfer_buf = (void *)call_arg.req_vaddr;
	ssize_t ret = (ssize_t)call_arg.resp_val;
	if(status){
		ret = -1;
	}
	else{
		memcpy(buf,transfer_buf,count);
	}
	if(mapped){
		eapp_unmap(transfer_buf,transfer_size);
	}
	return ret;
}
