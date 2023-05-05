#ifndef __FS_CLIENT__
#define __FS_CLIENT__
#include <sys/types.h>    
#include <sys/stat.h> 
#define PRE_MAP_SIZE 4096
unsigned long get_fs_handle();
// just pre_mapped one page in enclave for performance
// cause multi-thread is not supported inside the enclave
// so the pre_mapped_page is mutually exclusion by default
void* get_pre_mapped_page();
int cli_sys_open(const char* path,int flag);
void set_pre_map_page(unsigned long vaddr);
int penglai_fstat(int fd,  char* path, struct stat* st);
#endif