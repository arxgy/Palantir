/**
 * This program is a Privileged Enclave demo in Reusable Enclave case study,
 * which is supported to do nested attestation on a nested PE (reset module) and a NE (serverless payload w/o WASM runtime).
 * 
 *  by Anonymous Author @ Apr 4, 2024.
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
#define REWIND_LIMIT 1

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

int execute(unsigned long * args)
{
  char *elf_file_name = "/root/eval-payload";
  ocall_create_param_t create_param;

  /* parameter preparation */
  create_param.elf_file_ptr = (unsigned long) &create_param;
  create_param.encl_type = NORMAL_ENCLAVE; /* nesting create */
  create_param.stack_size = DEFAULT_STACK_SIZE;
  create_param.migrate_arg = 0;
  /* disable shm currently */
  create_param.shmid = 0;
  create_param.shm_offset = 0;
  create_param.shm_size = 0;
  unsigned long eid = get_enclave_id();
  unsigned long prev_time;
  eapp_print("[pe] [Reset Module] Allocated PE's eid: [%d]\n", eid);
  
  memcpy(create_param.elf_file_name, elf_file_name, ELF_FILE_LEN);  
  
  prev_time = get_cycle();
  int retval = eapp_create_enclave((unsigned long)(&create_param));
  eapp_print("[BREAKDOWN] CREATE time: %lx\n", get_cycle() - prev_time);
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
  // eapp_print("[pe] [Reset Module] report vaddr: [%p]", &report);
  retval = eapp_attest_enclave((unsigned long)(&attest_param));
  if (retval)
  {
    eapp_print("eapp_attest_enclave failed: %d\n",retval);
  }
  /* before run: snapshot (global variable, heap, stack) */

  int iter = 0, sum = 0, requested = 0;
  char *hash = report.enclave.hash;
  for (iter = 0 ; iter < HASH_SIZE; iter++)
  {
    sum = sum + (int) (hash[iter]);
    // eapp_print("%d|", sum);
  }
  eapp_print("\n[pe] [Reset Module] attestation sum: %d", sum);

  char content[PAGE_SIZE];
  memset((void *)content, 0, PAGE_SIZE);
  ocall_inspect_param_t inspect_param;
  inspect_param.inspect_result = (unsigned long)(content);

  ocall_request_t request_param;
  ocall_response_t response_param;
  ocall_request_rewind_t rewind_request_param;
  request_param.rewind_request = (unsigned long)(&rewind_request_param);
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

  // eapp_print("[pe] request_arg [%p], inspect_arg [%p].\n",
  //             (void *)(&request_param), (void *)(&inspect_request_param));
  retval = eapp_run_enclave((unsigned long)(&run_param));

  unsigned loop = 0;
  unsigned repeat = 0;
  while (retval == 0)
  {
    loop++;    
    requested = 0;
    switch (return_reason)
    {
      case NE_REQUEST_REWIND:
        requested = 1;
        repeat++;
        break;
      default:
        break;
    }
    if (return_reason == RETURN_USER_EXIT_ENCL)
    {
      eapp_print("[pe] [Reset Module] eapp_run_enclave return_value: [%d]\n", return_value);
      break;
    }
    /* we reuse the [return reason] as [resume reason] */
    if (retval)
    {
      eapp_print("[pe] [Reset Module] eapp_inspect_enclave return_value non-zero: [%d]\n", return_value);
      break;
    }
    run_param.resume_reason = return_reason;
    if (requested) {
      run_param.resume_reason = RETURN_USER_NE_REQUEST;
    }

    if (repeat <= REWIND_LIMIT)
      retval = eapp_resume_enclave((unsigned long)(&run_param));
    else 
      break;
  }

  
  EAPP_RETURN(0);

}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
}
