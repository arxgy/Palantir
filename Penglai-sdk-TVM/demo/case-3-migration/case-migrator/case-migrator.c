/**
 * This program is a Privileged Enclave demo in Live Enclave Migration case study (local ver),
 * which will 
 *  1. stoppped the Normal Enclave, dump files
 *  2. restore the Normal Enclave from given dump files, implement Live Migration.
 *  by Ganxiang Yang @ May 25, 2023.
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

#define DEFAULT_SNAPSHOT_STAGE  3
int hello(unsigned long * args)
{  
  char *elf_file_name = "/root/case-migratee";
  ocall_create_param_t create_param;

  /* parameter preparation */
  create_param.elf_file_ptr = (unsigned long) &create_param;
  create_param.encl_type = NORMAL_ENCLAVE;
  create_param.stack_size = DEFAULT_STACK_SIZE;
  /* disable shm currently */
  create_param.shmid = 0;
  create_param.shm_offset = 0;
  create_param.shm_size = 0;
  unsigned long eid = get_enclave_id();
  eapp_print("[pe] [inspector] Allocated PRIVIL ENCLAVE eid: [%d]\n", eid);

  memcpy(create_param.elf_file_name, elf_file_name, ELF_FILE_LEN);  
  int retval = eapp_create_enclave((unsigned long)(&create_param));
  if (retval)
  {
    eapp_print("eapp_create_enclave failed: %d\n",retval);
  }
  eapp_print("[pe] [inspector] Allocated NORMAL ENCLAVE eid: [%d]\n", create_param.eid);
  
  struct report_t report;
  ocall_attest_param_t attest_param;
  attest_param.attest_eid = create_param.eid;
  attest_param.isShadow = 0;
  attest_param.nonce = 4096;
  attest_param.report_ptr = (unsigned long)(&report);
  memset(&report, 0, sizeof(struct report_t));
  eapp_print("[pe] [inspector] report vaddr: [%p]", &report);
  retval = eapp_attest_enclave((unsigned long)(&attest_param));
  if (retval)
  {
    eapp_print("eapp_attest_enclave failed: %d\n",retval);
  }
  int iter = 0, sum = 0, requested = 0;
  char *hash = report.enclave.hash;
  for (iter = 0 ; iter < HASH_SIZE; iter++)
  {
    sum = sum + (int) (hash[iter]);
    // eapp_print("%d|", sum);
  }
  eapp_print("\n[pe] [inspector] attestation sum: %d", sum);

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

  eapp_print("[pe] request_arg [%p], inspect_arg [%p].\n",
              (void *)(&request_param), (void *)(&inspect_request_param));
  retval = eapp_run_enclave((unsigned long)(&run_param));

  enclave_mem_dump_t dump_arg;
  memset((void *)(&dump_arg), 0, sizeof(enclave_mem_dump_t));
  eapp_print("[pe] dump_arg size: [%lx]\n", sizeof(enclave_mem_dump_t));

  unsigned loop = 0;
  while (retval == 0)
  {
    if (loop == DEFAULT_SNAPSHOT_STAGE)
    {
      ocall_destroy_param_t destroy_param;
      destroy_param.destroy_eid = run_param.run_eid;
      destroy_param.op = DESTROY_SNAPSHOT;
      destroy_param.dump_arg = (unsigned long)(&dump_arg);
      /* do inspect & snapshot */
      retval = eapp_destroy_enclave((unsigned long)(&destroy_param));
      eapp_print("[pe] eapp_destroy_enclave return value is [%d]\n", retval);
      break;
    }
    loop++;
    requested = 0;
    switch (return_reason)
    { 
      case NE_REQUEST_DEBUG_PRINT:
        requested = 1;
      case NE_REQUEST_INSPECT:
        /* We don't perform any memory sharing service here. */
        break;
      case NE_REQUEST_SHARE_PAGE:
        /* We don't perform any memory sharing service here. */
        break;
      default:
        break;
    }
    if (return_reason == RETURN_USER_EXIT_ENCL)
    {
      eapp_print("[pe] [inspector] eapp_run_enclave return_value: [%d]\n", return_value);
      break;
    }
    /* we reuse the [return reason] as [resume reason] */
    if (retval)
    {
      eapp_print("[pe] [inspector] eapp_inspect_enclave return_value non-zero: [%d]\n", return_value);
      break;
    }
    run_param.resume_reason = return_reason;
    // For all request-interrupt, we provide a uniformed resume reason.
    if (requested)
    {
      run_param.resume_reason = RETURN_USER_NE_REQUEST;        
    }
    retval = eapp_resume_enclave((unsigned long)(&run_param));
  }

  /* Then we restore it from (vma) dump struct (locally). */

  /* exit successfully */
  eapp_print("[pe] [migrator] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
