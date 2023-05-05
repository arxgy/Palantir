#include"sys/stat.h"
#include "fsclient.h"
#include "fscallargs.h"
#include "eapp.h"
#include<string.h>
#include "print.h"
// #define LFS
static void* __page = 0;
unsigned long get_fs_handle(){
    static unsigned long _handle = -1UL;
    if(_handle == -1UL){
        #ifdef LFS
        _handle = acquire_enclave("lfs");
        #else
        _handle = acquire_enclave("filesystem");
        #endif
        if(_handle == -1UL){
            eapp_print("acquire filesystem encalve failed\n");
            EAPP_RETURN(-1);
        }
    }
    return _handle;
}

void* get_pre_mapped_page(){
    if(!__page){
        __page = eapp_mmap(0,PRE_MAP_SIZE);
    }
    return __page;
}

int cli_sys_open(const char* path,int flags){
	void* buf = get_pre_mapped_page();
	unsigned long handle = get_fs_handle();
	struct open_arg *open_arg = (struct open_arg *)(buf);
	strcpy(open_arg->path,path);
	open_arg->mode = flags;
    struct call_enclave_arg_t call_arg;
    call_arg.req_arg = FSOPEN;
    call_arg.req_vaddr = (unsigned long)buf;
    call_arg.req_size = PRE_MAP_SIZE;
	int status = call_enclave(handle,&call_arg);
    set_pre_map_page(call_arg.req_vaddr);
	if(status){
        return -1;
    }
    else{
        return (int)call_arg.resp_val;
    }
}

void set_pre_map_page(unsigned long vaddr){
    __page = (void *)vaddr;
}
int penglai_fstat(int fd,  char* path, struct stat* st){
    void *buf = get_pre_mapped_page();
    unsigned long handle = get_fs_handle();
    struct stat_arg *stat_arg = (struct stat_arg*)buf;
    stat_arg->fd = fd;
    if(path != NULL)
      strcpy(stat_arg->path,path);
    struct call_enclave_arg_t call_arg;
    call_arg.req_arg = FSSTAT;
    call_arg.req_vaddr = (unsigned long)buf;
    call_arg.req_size = PRE_MAP_SIZE;
    int status = call_enclave(handle,&call_arg);
    set_pre_map_page(call_arg.req_vaddr);
    if(status){
        return -1;
    }
    else{
        st->st_size = call_arg.resp_val;
        return 0;
    }
}