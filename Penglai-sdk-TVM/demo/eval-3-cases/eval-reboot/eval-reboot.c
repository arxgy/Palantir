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
#define REWIND_LIMIT 8

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

int execute(unsigned long * args)
{
  char *elf_file_name = "/root/eval-workload";
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
  eapp_print("[pe] [Reset Module] Allocated PE's eid: [%d]\n", eid);
  
  memcpy(create_param.elf_file_name, elf_file_name, ELF_FILE_LEN); 

  char content[PAGE_SIZE];
  memset((void *)content, 0, PAGE_SIZE);
  ocall_inspect_param_t inspect_param;
  inspect_param.inspect_result = (unsigned long)(content);
  struct report_t report;
  
  ocall_attest_param_t attest_param;
  attest_param.isShadow = 0;
  attest_param.nonce = 4096;
  attest_param.report_ptr = (unsigned long)(&report);
  
  ocall_request_t request_param;
  ocall_response_t response_param;
  ocall_request_rewind_t rewind_request_param;
  request_param.rewind_request = (unsigned long)(&rewind_request_param);
  response_param.inspect_response = NULL;
  response_param.share_page_response = NULL;
  ocall_request_dump_t *dump_context = NULL;
  ocall_run_param_t run_param;
  int return_reason, return_value;
  run_param.reason_ptr = (unsigned long)(&return_reason);
  run_param.retval_ptr = (unsigned long)(&return_value);
  run_param.request_arg = (unsigned long)(&request_param);
  run_param.response_arg = (unsigned long)(&response_param);


  memset(&report, 0, sizeof(struct report_t));

  for (int repeat = 0 ; repeat < 1 ; repeat++)
  { 
  	eapp_print("Workload Start Creating!: %lx (cycle)\n", get_cycle());
    int retval = eapp_create_enclave((unsigned long)(&create_param));
    if (retval)
    {
      eapp_print("eapp_create_enclave failed: %d\n",retval);
    }
    attest_param.attest_eid = create_param.eid;

    retval = eapp_attest_enclave((unsigned long)(&attest_param));
    if (retval)
    {
      eapp_print("eapp_attest_enclave failed: %d\n",retval);
    }
    int iter = 0, sum = 0, requested = 0;
    char *hash = report.enclave.hash;
    for (iter = 0 ; iter < HASH_SIZE; iter++)
      sum = sum + (int) (hash[iter]);

    run_param.run_eid = create_param.eid;
    retval = eapp_run_enclave((unsigned long)(&run_param));

    unsigned loop = 0;
    while (retval == 0)
    {
      loop++;    
      requested = 0;
      switch (return_reason)
      {
        case NE_REQUEST_REWIND:
          requested = 1;
          break;
        default:
          break;
      }
      if (return_reason == RETURN_USER_EXIT_ENCL)
        break;
      /* we reuse the [return reason] as [resume reason] */
      if (retval)
      {
        eapp_print("[pe] [Reset Module] return_value non-zero: [%d]\n", return_value);
        break;
      }
      run_param.resume_reason = return_reason;
      if (requested) {
        run_param.resume_reason = RETURN_USER_NE_REQUEST;
      }
      retval = eapp_resume_enclave((unsigned long)(&run_param));
    }
    ocall_destroy_param_t destroy_param;
    destroy_param.destroy_eid = run_param.run_eid;
    // retval = eapp_destroy_enclave((unsigned long)(&destroy_param));
  }
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
}
