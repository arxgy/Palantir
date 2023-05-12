#include "eapp.h"
#include "print.h"
#include "privil.h"
#include <stdlib.h>
#include <string.h>
#include "fscallargs.h"
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#define DEFAULT_STACK_SIZE  64*1024

int hello(unsigned long * args)
{
  // unsigned long size;
  /* PRIVIL ENCLAVE, read elf file */
  // eapp_print("before fopen\n");
  char *elf_file_name = "/root/ne-hello";
  ocall_create_param_t param;

  /* parameter preparation */
  param.elf_file_ptr = (unsigned long) &param;
  // param.elf_file_size = size;  
  param.encl_type = NORMAL_ENCLAVE;
  param.stack_size = DEFAULT_STACK_SIZE;
  /* disable shm currently */
  param.shmid = 0;
  param.shm_offset = 0;
  param.shm_size = 0;
  unsigned long eid = get_enclave_id();
  printf("Allocated PRIVIL ENCLAVE eid: [%d]\n", eid);

  memcpy(param.elf_file_name, elf_file_name, ELF_FILE_LEN);  
  int retval = eapp_create_enclave((unsigned long)(&param));
  if (retval)
  {
    eapp_print("eapp_create_enclave failed: %d\n",retval);
  }
  // fclose(f);
  printf("Allocated NORMAL ENCLAVE eid: [%d]\n", param.eid);
  printf("hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
