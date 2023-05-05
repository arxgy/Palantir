#include "types.h"
#include "defs.h"
#include "param.h"
#include "buf.h"
#include "bio_interface.h"
#include "eapp.h"
#include "print.h"
#include "string.h"
#define PREMAPED_SIZE (4096*2)
int inited = 0;
int EAPP_ENTRY main(){
    unsigned long *args;
    EAPP_RESERVE_REG;
    // eapp_print("bio server begin to run\n");   
    if(!inited){
        binit();
        inited = 1;
        eapp_print("bio server inited\n");
    }
    unsigned long service_type = args[10];
    struct call_enclave_arg_t ret_arg;
    void * req_buf = args[11];
    switch (service_type)
    {
    case INITLOG:
    {
        // eapp_print("initlog\n");
        struct initlog_arg *arg = (struct initlog_arg*)req_buf;
        initlog(arg->dev,arg->logstart, arg->nlog);
        ret_arg.req_vaddr = args[11];
        ret_arg.req_size = args[12];
        ret_arg.resp_val = 0;
        ret_arg.resp_vaddr = 0;
        ret_arg.resp_size = 0;
        SERVER_RETURN(&ret_arg);
        break;
    }
    case BEGIN_OP:
    {
        // eapp_print("bigin_op\n");
        begin_op();
        ret_arg.req_vaddr = args[11];
        ret_arg.req_size = args[12];
        ret_arg.resp_val = 0;
        ret_arg.resp_vaddr = 0;
        ret_arg.resp_size = 0;
        SERVER_RETURN(&ret_arg);
        break;
    }
    case END_OP:
    {
        // eapp_print("end_op\n");
        end_op();
        ret_arg.req_vaddr = args[11];
        ret_arg.req_size = args[12];
        ret_arg.resp_val = 0;
        ret_arg.resp_vaddr = 0;
        ret_arg.resp_size = 0;
        SERVER_RETURN(&ret_arg);
    }
    case BREAD:
    {
        struct bread_call_arg *read_arg = (struct bread_call_arg*)(args[11]);
        // eapp_print("BREAD: blockno: %d\n",read_arg->blockno);
        struct buf* b = bread(read_arg->dev, read_arg->blockno);
        ret_arg.req_size = args[12];
        ret_arg.req_vaddr = args[11];
        ret_arg.resp_val = 0;
        ret_arg.resp_vaddr = b;
        ret_arg.resp_size = PREMAPED_SIZE;
        // eapp_print("BREAD: b: 0x%lx\n",b);
        SERVER_RETURN(&ret_arg);
        break;
    }
    case BRELSE:
    {
        // eapp_print("BRELSE\n");
        struct buf *b = (struct buf*)args[11];
        brelse(b);
        ret_arg.req_size = 0;
        ret_arg.req_vaddr = NULL;
        ret_arg.resp_val = 0;
        ret_arg.resp_vaddr = 0;
        ret_arg.resp_size = 0;
        SERVER_RETURN(&ret_arg);
        break;
    }
    case LOG_WRITE:
    {
        // eapp_print("LOG_WRITE\n");
        struct buf *b = (struct buf*)args[11];
        // eapp_print("LOG_WRITE: index: %d\n",b->index);
        log_write(b);
        ret_arg.req_size = args[12];
        ret_arg.req_vaddr = args[11];
        ret_arg.resp_val = 0;
        ret_arg.resp_vaddr = 0;
        ret_arg.resp_size = 0;
        SERVER_RETURN(&ret_arg);
        break; 
    }
    default:
        break;
    }
}