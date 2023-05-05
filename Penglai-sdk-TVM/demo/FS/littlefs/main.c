#include<stdio.h>
#include<string.h>
#include "lfs.h"
#include "lfsram.h"
#include "eapp.h"
#include "print.h"
#include "lfscallargs.h"
#define MAX_FILES 256
static lfs_t lfs;

static int inited = 0;
static lfs_file_t open_files[MAX_FILES];
static char used[MAX_FILES/8];
static char open_file_paths[MAX_FILES][MAXPATH];
const struct lfs_config cfg = {
    .read = ram_read,
    .prog = ram_prog,
    .erase = ram_erase,
    .sync = ram_sync,
    .read_size = 16,
    .prog_size = 16,
    .block_size = 4096,
    .block_count = 128,
    .cache_size = 16,
    .lookahead_size = 16,
    .block_cycles = 500,
    .name_max = MAXPATH,
};

int init(){ // mount the fs
    int err;
    err = lfs_mount(&lfs,&cfg);
    if(err){
        lfs_format(&lfs, &cfg);
        err = lfs_mount(&lfs, &cfg);
        if(err){
            eapp_print("mount failed after reformat\n");
            return -1;
        }
    }
    used[0] = 7; // so fd start from 3
    // lfs_file_t test_file;
    // err = lfs_file_open(&lfs,&open_files[0], "/hello.txt",577);
    // if(err < 0){
    //     eapp_print("[lfs]: create /hello.txt failed, err: %d\n",err);
    // }
    // else{
    //     eapp_print("create /hello.txt succeed\n");
    //  }
    return 0;
}

int is_set(int index){
    char mask = 1 << (index % 8);
    return used[index/8] & mask;
}

int get_free_file_index(){
    for(int i = 0; i < MAX_FILES;i++){
        if(is_set(i)){
            continue;
        }
        else{
            return i;
        }
    }
    return -1;
}

void set_used_file_index(int index){
    if(is_set(index)){
        eapp_print("[lfs]: error! file already used\n");
    }
    else{
        char mask = 1 << (index % 8);
        used[index / 8] |= mask;
    }
}
void set_unused_file_index(int index){
    if(!is_set(index)){
        eapp_print("[lfs]: error! file already free\n");
    }
    else{
        char mask = 1 << (index % 8);
        used[index/8] &= ~mask;
    }
}



int EAPP_ENTRY main(){
    unsigned long* args;
    EAPP_RESERVE_REG;
#if 0
    int err;
    lfs_format(&lfs,&cfg);
    err = lfs_mount(&lfs,&cfg);
    if(err < 0){
        eapp_print("lfs mount failed\n");
        EAPP_RETURN(-1);
    }
    eapp_print("lfs mount succeed\n");
    lfs_file_t file;
    err = lfs_file_open(&lfs, &file,"hello.txt", LFS_O_RDWR|LFS_O_CREAT);
    if(err < 0){
        eapp_print("open hello.txt failed\n");
    }
    EAPP_RETURN(err);
#endif
    int err;
    unsigned long type = args[10];
    struct call_enclave_arg_t ret_arg;
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];
    ret_arg.resp_vaddr = 0;
    ret_arg.resp_size = 0;
    if(!inited){
        err = init();
        if(err){
            ret_arg.resp_val = -1;
            SERVER_RETURN(&ret_arg);
        }
        inited = 1;
        eapp_print("lfs mount succeed\n");
    }
    // eapp_print("[lfs]: debug: type: %d\n",type);
    switch (type)
    {
    case FSOPEN:
        {
            struct open_arg* arg = (struct open_arg*)args[11];
            int fd = get_free_file_index();
            // eapp_print("open: fd: %d, flags: %d, path: %s\n",fd,arg->mode,arg->path);
            if(fd == -1){
                eapp_print("[lfs]: error! too many open files\n");
                ret_arg.resp_val = -1;
                SERVER_RETURN(&ret_arg);
            }
            err = lfs_file_open(&lfs,&open_files[fd],arg->path, arg->mode);
            // eapp_print("lfs_file_open: err: %d\n",err);
            if(err){
                ret_arg.resp_val = err;
                SERVER_RETURN(&ret_arg);
            }
            else{
                strcpy(open_file_paths[fd], arg->path);
                ret_arg.resp_val = fd;
                set_used_file_index(fd);
                SERVER_RETURN(&ret_arg);
            }
            break;
        }
    case FSCLOSE:
        {
            struct close_arg *arg = (struct close_arg*)args[11];
            if(arg->fd >= MAX_FILES){
                ret_arg.resp_val = -1;
                SERVER_RETURN(&ret_arg);
            }
            if(!is_set(arg->fd)){
                ret_arg.resp_val = -1;
                SERVER_RETURN(&ret_arg);
            }
            else{
                err = lfs_file_close(&lfs,&open_files[arg->fd]);
                ret_arg.resp_val = err;
                if(!err){
                    set_unused_file_index(arg->fd);
                    open_file_paths[arg->fd][0] = 0;
                }
                SERVER_RETURN(&ret_arg);
            }
            break;
        }
    case FSREAD:
        {
            struct read_arg *arg = (struct read_arg*)args[11];
            int fd = arg->fd;
            int size = arg->size;
            if(size > args[12] || fd >= MAX_FILES){
                ret_arg.resp_val = -1;
                SERVER_RETURN(&ret_arg);
            }
            int read_size = lfs_file_read(&lfs,&open_files[fd],(void*)args[11],size);
            ret_arg.resp_val = read_size;
            SERVER_RETURN(&ret_arg);
            break;
        }
    case FSWRITE:
        {
            struct write_arg *arg = (struct write_arg*)args[11];
            int fd = arg->fd;
            int size = arg->size;
            if(size + sizeof(struct write_arg) > args[12] || fd >= MAX_FILES){
                ret_arg.resp_val = -1;
                SERVER_RETURN(&ret_arg);
            }
            int write_size = lfs_file_write(&lfs,&open_files[fd],(char*)args[11] + sizeof(struct write_arg), size);
            ret_arg.resp_val = write_size;
            SERVER_RETURN(&ret_arg);
            break;
        }
    case FSLSEEK:
        {
            struct lseek_arg *arg = (struct lseek_arg*)args[11];
            if(arg->fd >= MAX_FILES){
                ret_arg.resp_val = -1;
                SERVER_RETURN(&ret_arg);
            }
            ret_arg.resp_val = lfs_file_seek(&lfs,&open_files[arg->fd],arg->offset,arg->whence);
            SERVER_RETURN(&ret_arg);
            break;
        }
    case FTRUNCATE:
        {
            struct ftruncate_arg *arg = (struct ftruncate_arg*)args[11];
            if(arg->fd >= MAX_FILES){
                ret_arg.resp_val = -1;
                SERVER_RETURN(&ret_arg);
            }
            ret_arg.resp_val = lfs_file_truncate(&lfs,&open_files[arg->fd],0);
            SERVER_RETURN(&ret_arg);
            break;
        }
    case UNLINK:
        {
            struct unlink_arg *arg = (struct unlink_arg*)args[11];
            ret_arg.resp_val = lfs_remove(&lfs,arg->path);
            SERVER_RETURN(&ret_arg);
            break;
        }
    case FSMKDIR:
        {
            struct mkdir_arg *arg = (struct mkdir_arg*)args[11];
            ret_arg.resp_val = lfs_mkdir(&lfs,arg->path);
            SERVER_RETURN(&ret_arg);
            break;
        }
    case FSSTAT:
    {
         struct stat_arg *stat_arg = (struct stat_arg*)args[11];
         struct lfs_info info;
         if(lfs_stat(&lfs, open_file_paths[stat_arg->fd], &info) != 0)
         {
             eapp_print("[lfs]: file stat %s error\n", stat_arg->path);
             ret_arg.resp_val = 0;
         }
         else
         {
             ret_arg.resp_val = info.size;
         }
         SERVER_RETURN(&ret_arg);
         break;
    }
    default:
        {
            eapp_print("[lfs]: unrecognized operation type %d!\n", type);
            SERVER_RETURN(&ret_arg);
            break;
        }
    }
}
