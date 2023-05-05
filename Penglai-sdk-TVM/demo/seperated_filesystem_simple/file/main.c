#include "eapp.h"
#include "types.h"
#include "stdio.h"
#include "defs.h"
#include "file.h"
#include "fcntl.h"
#include "string.h"
#include "print.h"
#include "fscallargs.h"

int inited = 0;

void init(){
  eapp_print("filesystem init2\n");
  iinit();
  binit();
  fsinit(1);
  fileinit();
}
int EAPP_ENTRY main(){
  unsigned long * args; // args
  EAPP_RESERVE_REG;
  // eapp_print("seperated filesystem server begin to run\n");
  if(!inited){
    init();
    //init bio
    inited = 1;
    eapp_print("filesystem server inited\n");
  }
  unsigned long type = args[10];
  struct call_enclave_arg_t ret_arg;
  ret_arg.resp_vaddr = 0;
  ret_arg.resp_size = 0;
  switch (type)
  {
  case FSOPEN:
  {
    struct open_arg *arg = (struct open_arg*)args[11];
    // eapp_print("server: FSOPEN, path: %s\n",arg->path);
    int fd = sys_open(arg->path,arg->mode);
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    ret_arg.resp_val = fd;
    SERVER_RETURN(&ret_arg);
    break;
  }
  case FSCLOSE:
  {
    
    struct close_arg *close_arg = (struct close_arg*)args[11];
    // eapp_print("server: FSCLOSE, fd: %d\n",close_arg->fd);
    int status = sys_close(close_arg->fd);
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    ret_arg.resp_val = status;
    SERVER_RETURN(&ret_arg);
    break;
  }
  case FSREAD:
  {
    
    int fd = ((struct read_arg*)args[11])->fd;
    int size = ((struct read_arg*)args[11])->size;
    // eapp_print("server: FSREAD, fd: %d, size: %d\n",fd,size);
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    if(size > args[12]){
      ret_arg.resp_val = -1;
      SERVER_RETURN(&ret_arg);
    }
    // eapp_print("server: read_fd: %d\n",fd);
    int read_size = sys_read(fd,args[11],size);
    // eapp_print("server: read size: %d\n",read_size);
    ret_arg.resp_val = read_size;
    SERVER_RETURN(&ret_arg);
    break;
  }
  case FSWRITE:
  {
    
    int fd = ((struct write_arg*)args[11])->fd;
    int size = ((struct write_arg*)args[11])->size;
    // eapp_print("server: FSWRITE, fd: %d, size: %d\n",fd,size);
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    if(size + sizeof(struct write_arg) > args[12]){
      ret_arg.resp_val = -1;
      SERVER_RETURN(&ret_arg);
    }
    char* write_buf = (char*)args[11] + sizeof(struct write_arg);
    int write_size = sys_write(fd,write_buf,size);
    ret_arg.resp_val = write_size;
    SERVER_RETURN(&ret_arg);
    break;
  }
  case FSLSEEK:
  {
    struct lseek_arg *lseek_arg = (struct lseek_arg*)args[11];
    int fd = lseek_arg->fd;
    int offset = lseek_arg->offset;
    int whence = lseek_arg->whence;
    // eapp_print("server: FSLSEEK,fd: %d, offset: %d, whence: %d\n",fd,offset,whence);
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    int ret = sys_lseek(fd,offset,whence);
    ret_arg.resp_val = ret;
    SERVER_RETURN(&ret_arg);
    break;
  }
  case FTRUNCATE:
  {
    struct ftruncate_arg *ftruncate_arg = (struct ftruncate_arg*)args[11];
    int fd = ftruncate_arg->fd;
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    // eapp_print("server: FTRUNCATE, fd: %d\n",fd);
    int ret = sys_ftruncate(fd);
    ret_arg.resp_val = ret;
    SERVER_RETURN(&ret_arg);
    break;
  }
  case UNLINK:
  {
    struct unlink_arg *unlink_arg = (struct unlink_arg*)args[11];
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    // eapp_print("server: unlink path: %s\n",unlink_arg->path);
    int ret = sys_unlink(unlink_arg->path);
    ret_arg.resp_val = ret;
    SERVER_RETURN(&ret_arg);
    break;
  }
  case FSMKDIR:
  {
    // eapp_print("FSMKDIR\n");
    struct mkdir_arg *mkdir_arg = (struct mkdir_arg*)args[11];
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    int ret = sys_mkdir(mkdir_arg->path);
    ret_arg.resp_val = ret;
    SERVER_RETURN(&ret_arg);
    break;
  }
  case FSSTAT:
  {
      struct stat_arg *stat_arg = (struct stat_arg*)args[11];
      ret_arg.req_vaddr = args[11];
      ret_arg.req_size = args[12];
      int fd;
      if(stat_arg->fd == -1){
        fd = sys_open(stat_arg->path,XV6_O_RDONLY);
        if(fd < 0){
          ret_arg.resp_val = 0;
        }
        else{
          ret_arg.resp_val = sys_file_size(fd);
          sys_close(fd);
        }
      }
      else{
        ret_arg.resp_val = sys_file_size(stat_arg->fd);
      }
      SERVER_RETURN(&ret_arg);
      break;
  }
  default:
    eapp_print("unrecognied type\n");
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    ret_arg.resp_val = -1;
    SERVER_RETURN("&ret_arg");
    break;
  }  
}
