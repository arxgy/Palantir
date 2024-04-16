/**
 * This program is a Privileged Enclave demo in Standard Evaluation.
 * It will load chain-1bench cases as a Normal Enclave and execute it.
 *  by Anonymous Author @ May 27, 2023.
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


int hello(unsigned long * args)
{  
  char *elf_file_name = "/root/chain-6";
  ocall_create_param_t create_param;

  /* parameter preparation */
  create_param.elf_file_ptr = (unsigned long) &create_param;
  create_param.encl_type = PRIVIL_ENCLAVE;
  create_param.stack_size = DEFAULT_STACK_SIZE;
  create_param.migrate_arg = 0;
  /* disable shm currently */
  create_param.shmid = 0;
  create_param.shm_offset = 0;
  create_param.shm_size = 0;
  unsigned long eid = get_enclave_id();

  memcpy(create_param.elf_file_name, elf_file_name, ELF_FILE_LEN);  
  int retval = eapp_create_enclave((unsigned long)(&create_param));
  if (retval)
  {
    eapp_print("eapp_create_enclave failed: %d\n",retval);
  }
  struct report_t report;
  ocall_attest_param_t attest_param;
  attest_param.attest_eid = create_param.eid;
  attest_param.isShadow = 0;
  attest_param.nonce = 4096;
  attest_param.report_ptr = (unsigned long)(&report);
  memset(&report, 0, sizeof(struct report_t));
  retval = eapp_attest_enclave((unsigned long)(&attest_param));
  if (retval)
  {
    eapp_print("eapp_attest_enclave failed: %d\n",retval);
  }
  int iter = 0, sum = 0;
  char *hash = report.enclave.hash;
  for (iter = 0 ; iter < HASH_SIZE; iter++)
  {
    sum = sum + (int) (hash[iter]);
  }

  char content[PAGE_SIZE];
  memset((void *)content, 0, PAGE_SIZE);
  ocall_inspect_param_t inspect_param;
  inspect_param.inspect_result = (unsigned long)(content);

  ocall_request_t request_param;
  ocall_response_t response_param;
  ocall_request_inspect_t inspect_request_param;
  request_param.inspect_request = (unsigned long)(&inspect_request_param);
  response_param.inspect_response = NULL;
  response_param.share_page_response = NULL;
  ocall_request_dump_t *dump_context = NULL;

  ocall_run_param_t run_param;
  int return_reason, return_value;
  run_param.run_eid = create_param.eid;
  run_param.reason_ptr = (unsigned long)(&return_reason);
  run_param.retval_ptr = (unsigned long)(&return_value);
  run_param.request_arg = (unsigned long)(&request_param);
  run_param.response_arg = (unsigned long)(&response_param);

  retval = eapp_run_enclave((unsigned long)(&run_param));

  while (retval == 0)
  {
    if (return_reason == RETURN_USER_EXIT_ENCL)
    {
      eapp_print("[pe] [chain-7] eapp_run_enclave returned! \n");
      break;
    }
    /* we reuse the [return reason] as [resume reason] */
    if (retval)
    {
      eapp_print("[pe] [chain-7] eapp_inspect_enclave return_value non-zero: [%d]\n", return_value);
      break;
    }
    run_param.resume_reason = return_reason;
    retval = eapp_resume_enclave((unsigned long)(&run_param));
  }

  /* exit successfully */
  eapp_print("[pe] [chain-7] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
