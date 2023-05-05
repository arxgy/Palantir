#if 0
#include "stdlib.h"
#include "eapp.h"
#include "print.h"
#include "types.h"
#include "bio_interface.h"
#include "fs.h"
#include "buf.h"
#include "string.h"
#define PREMAPSIZE 4096*2
static unsigned long __bio_handle = -1UL;
static void *__pre_mapped_buf = 0;
unsigned long get_bio_handle(){
    if(__bio_handle == -1UL){
        __bio_handle = acquire_enclave("bio");
        if(__bio_handle == -1UL){
            eapp_print("get_bio_handle failed\n");
        }
    }
    return __bio_handle;
}

void* get_premapped_buf(){
    if(!__pre_mapped_buf){
        __pre_mapped_buf = eapp_mmap(0,PREMAPSIZE);
    }
    return __pre_mapped_buf;
}

void begin_op(){
    struct call_enclave_arg_t call_arg;
    call_arg.req_size = 0;
    call_arg.req_vaddr = NULL;
    call_arg.req_arg = BEGIN_OP;
    unsigned long handle = get_bio_handle();
    call_enclave(handle,&call_arg);
}

void end_op(){
    struct call_enclave_arg_t call_arg;
    call_arg.req_size = 0;
    call_arg.req_vaddr = NULL;
    call_arg.req_arg = END_OP;
    unsigned long handle = get_bio_handle();
    call_enclave(handle,&call_arg);  
}

struct buf* bread(unsigned int dev, unsigned int blockno){
    struct bread_call_arg * bread_arg = (struct bread_call_arg*)get_premapped_buf();
    bread_arg->dev = dev;
    bread_arg->blockno = blockno;
    struct call_enclave_arg_t call_arg;
    call_arg.req_arg = BREAD;
    call_arg.req_vaddr = bread_arg;
    call_arg.req_size = PREMAPSIZE;
    call_enclave(get_bio_handle(),&call_arg);
    return (struct buf*)(call_arg.resp_vaddr);
}

void log_write(struct buf * b){
    struct call_enclave_arg_t call_arg;
    call_arg.req_vaddr = b;
    call_arg.req_size = PREMAPSIZE;
    call_arg.req_arg = LOG_WRITE;
    call_enclave(get_bio_handle(),&call_arg);
    b = call_arg.req_vaddr;
}

void brelse(struct buf *b){
    struct call_enclave_arg_t call_arg;
    call_arg.req_vaddr = b;
    call_arg.req_size = PREMAPSIZE;
    call_arg.req_arg = BRELSE;
    call_enclave(get_bio_handle(),&call_arg);
    b = NULL;
}
void panic(const char* s){
    eapp_print("panic: %s\n",s);
}

void initlog(uint dev,struct superblock* sb){
    struct initlog_arg* initlog_arg = get_premapped_buf();
    initlog_arg->dev = dev;
    initlog_arg->logstart = sb->logstart;
    initlog_arg->nlog = sb->nlog;
    struct call_enclave_arg_t call_arg;
    call_arg.req_arg = INITLOG;
    call_arg.req_vaddr = initlog_arg;
    call_arg.req_size = PREMAPSIZE;
    call_enclave(get_bio_handle(),&call_arg);
}
#endif
