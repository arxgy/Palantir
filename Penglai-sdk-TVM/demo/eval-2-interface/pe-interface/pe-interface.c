/**
 * This program is a Privileged Enclave demo in Interface-level Evaluation.
 * It will create 2^n enclaves and calculate time cost.
 *  by Ganxiang Yang @ May 28, 2023.
*/
#include "eapp.h"
#include "print.h"
#include "privil.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define ENTRY_POINT 0x1000
#define DEFAULT_INSPECT_TEXT_SIZE   512
#define DEFAULT_INSPECT_STACK_SIZE  256
#define DEFAULT_STACK_SIZE  64*1024

#define LOG_BATCH_SIZE 8
#define BATCH_SIZE  1<<LOG_BATCH_SIZE
int hello(unsigned long * args)
{  
  char *elf_file_name = "/root/hello-world";
  ocall_create_param_t create_param;

  /* parameter preparation */
  create_param.elf_file_ptr = (unsigned long) &create_param;
  create_param.encl_type = NORMAL_ENCLAVE;
  create_param.stack_size = DEFAULT_STACK_SIZE;
  create_param.migrate_arg = 0;
  /* disable shm currently */
  create_param.shmid = 0;
  create_param.shm_offset = 0;
  create_param.shm_size = 0;

  memcpy(create_param.elf_file_name, elf_file_name, ELF_FILE_LEN);  
  
  int i, retval;
  unsigned int idr_eids[BATCH_SIZE];
  unsigned long create_cycle, attest_cycle, begin_cycle, end_cycle;
  for (i = 0 ; i < BATCH_SIZE ; i++)
  {
    asm volatile("rdcycle %0" : "=r"(begin_cycle));
    retval = eapp_create_enclave((unsigned long)(&create_param));
    asm volatile("rdcycle %0" : "=r"(end_cycle));
    create_cycle += (end_cycle - begin_cycle);
    idr_eids[i] = create_param.eid;
    if (retval)
    {
      eapp_print("eapp_create_enclave failed: %d\n",retval);
      EAPP_RETURN(1);
    }
  }
  create_cycle = create_cycle >> LOG_BATCH_SIZE; // avg

  struct report_t report;
  ocall_attest_param_t attest_param;
  attest_param.attest_eid = create_param.eid;
  attest_param.isShadow = 0;
  attest_param.nonce = 4096;
  attest_param.report_ptr = (unsigned long)(&report);
  memset(&report, 0, sizeof(struct report_t));
  for (i = 0 ; i < BATCH_SIZE ; i++)
  {
    attest_param.attest_eid = idr_eids[i];
    asm volatile("rdcycle %0" : "=r"(begin_cycle));
    retval = eapp_attest_enclave((unsigned long)(&attest_param));
    asm volatile("rdcycle %0" : "=r"(end_cycle));
    attest_cycle += (end_cycle - begin_cycle);
    if (retval)
    {
      eapp_print("eapp_attest_enclave failed: %d\n",retval);
      EAPP_RETURN(2);
    }
  }
  attest_cycle = attest_cycle >> LOG_BATCH_SIZE;
  
  printf("[pe] [eval-interface] host creating %d enclave costs %ld cycles in average\n", BATCH_SIZE, create_cycle);
  printf("[pe] [eval-interface] host attesting %d enclave costs %ld cycles in average\n", BATCH_SIZE, attest_cycle);
  
  /* exit successfully */
  eapp_print("[pe] [eval-interface] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
