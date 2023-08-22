/**
 * This program is a Privileged Enclave demo in Memory Inspection evaluation,
 * which do live enclave memory inspection on target Normal Enclave.
 * The Privileged Enclave accept inspect request and sequentially do inspection by different sizes.
 *  by Anonymous Author @ May 28, 2023.
*/
#include "eapp.h"
#include "print.h"
#include "privil.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/** 
 * Set NE default parameter here. 
 * Specifically, these parameter should be get from eapp_create_enclave,
 * which is left to our future work.
 *  by Anonymous Author @ May 24, 2023.
*/
#define ENTRY_POINT 0x1000
#define DEFAULT_INSPECT_TEXT_SIZE   512
#define DEFAULT_INSPECT_STACK_SIZE  256
#define DEFAULT_STACK_SIZE  64*1024

#define SAMPLE_NUM  20

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

int hello(unsigned long * args)
{  
  /** add a more complete lib & interface in future. 
   *  now we call eapp_call directly
   */
  char *elf_file_name = "/root/eval-inspectee";
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
  unsigned long eid = get_enclave_id();
  eapp_print("[pe] [inspector] Allocated PRIVIL ENCLAVE eid: [%d]\n", eid);

  memcpy(create_param.elf_file_name, elf_file_name, ELF_FILE_LEN);  
  int retval = eapp_create_enclave((unsigned long)(&create_param));
  if (retval)
  {
    eapp_print("eapp_create_enclave failed: %d\n",retval);
  }
  eapp_print("[pe] [inspector] Allocated NORMAL ENCLAVE eid: [%d]\n", create_param.eid);


  char *content = (char *)eapp_mmap(NULL, 1<<26);
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

  unsigned long sample_sz[SAMPLE_NUM] = 
    {1,    2,    4,    8,     16, 
     32,   64,   96,   128,   192,
     256,  512,  768,  1024,  2048,
     4096, 6144, 8192, 12288, 16384};
  int i, j;
  unsigned long begin_cycle, end_cycle, sum_cycle, requested;
  while (retval == 0)
  {
    requested = 0;
    switch (return_reason)
    {
      case NE_REQUEST_INSPECT:
        requested = 1;
        inspect_param.dump_context = INSPECT_MEM;
        inspect_param.inspect_eid = run_param.run_eid;
        inspect_param.inspect_size = PAGE_SIZE;
        for (i = 0 ; i < SAMPLE_NUM ; i++)
        {
          inspect_param.inspect_address = inspect_request_param.inspect_ptr;
          sum_cycle = 0;
          for (j = 0 ; j < sample_sz[i] ; j++)
          {
            begin_cycle = get_cycle();
            eapp_inspect_enclave((unsigned long)(&inspect_param));
            end_cycle = get_cycle();
            sum_cycle += (end_cycle - begin_cycle);
            inspect_param.inspect_address += PAGE_SIZE;
          }
          eapp_print("[pe] [eval-inspector] Inspect on sample [%d] cost: [%lx] (cycle)\n", i, (sum_cycle));
        }
        break;
      default:
        break;
    }
    if (return_reason == RETURN_USER_EXIT_ENCL)
    {
      eapp_print("[pe] [inspector] eapp_run_enclave return_value: [%d]\n", return_value);
      break;
    }
    if (retval)
    {
      eapp_print("[pe] [inspector] eapp_inspect_enclave return_value non-zero: [%d]\n", return_value);
      break;
    }
    run_param.resume_reason = return_reason;
    if (requested)
    {
      run_param.resume_reason = RETURN_USER_NE_REQUEST;        
    }
    retval = eapp_resume_enclave((unsigned long)(&run_param));
  }

  /* exit successfully */
  eapp_print("[pe] [eval-inspector] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
