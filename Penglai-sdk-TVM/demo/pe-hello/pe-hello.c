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
  ocall_create_param_t create_param;

  /* parameter preparation */
  create_param.elf_file_ptr = (unsigned long) &create_param;
  // create_param.elf_file_size = size;  
  create_param.encl_type = NORMAL_ENCLAVE;
  create_param.stack_size = DEFAULT_STACK_SIZE;
  /* disable shm currently */
  create_param.shmid = 0;
  create_param.shm_offset = 0;
  create_param.shm_size = 0;
  unsigned long eid = get_enclave_id();
  eapp_print("Allocated PRIVIL ENCLAVE eid: [%d]\n", eid);

  memcpy(create_param.elf_file_name, elf_file_name, ELF_FILE_LEN);  
  int retval = eapp_create_enclave((unsigned long)(&create_param));
  if (retval)
  {
    eapp_print("eapp_create_enclave failed: %d\n",retval);
  }
  eapp_print("Allocated NORMAL ENCLAVE eid: [%d]\n", create_param.eid);
  
  /** add a more complete lib & interface in future. 
   *  now we call eapp_call directly
   */
  struct report_t report;
  ocall_attest_param_t attest_param;
  attest_param.attest_eid = create_param.eid;
  attest_param.isShadow = 0;
  attest_param.nonce = 4096;
  attest_param.report_ptr = (unsigned long)(&report);
  memset(&report, 0, sizeof(struct report_t));
  eapp_print("[pe] report vaddr: [%p]", &report);
  eapp_attest_enclave((unsigned long)(&attest_param));

  int iter = 0, sum = 0;
  char *hash = report.enclave.hash;
  for (iter = 0 ; iter < HASH_SIZE; iter++)
  {
    sum = sum + (int) (hash[iter]);
    // eapp_print("%d|", sum);
  }
  eapp_print("\n[pe] attestation sum: %d", sum);
  eapp_print("hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
