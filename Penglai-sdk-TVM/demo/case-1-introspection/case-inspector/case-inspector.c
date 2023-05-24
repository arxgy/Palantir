/**
 * This program is a Privileged Enclave demo in Memory Inspection case study,
 * which is supported to do live enclave memory introspection on a vulnerable Normal Enclave.
 * Specifically, Privileged Enclave can either accept inspect request or actively do mandatory inspection.
 * In this demo, the PE sequentially does: 
 *  1. Code Integrity Checking @ loop 0
 *  2. Context Dump @ loop 1
 *  3. Stack Integrity Checking @ EACH request
 *  4. Variable Inspection @ EACH request
 * Note that we can perform any inspection given above at any time. 
 * As a demo we only perform some of them on several loops from NE startup.
 *  by Ganxiang Yang @ May 24, 2023.
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
 *  by Ganxiang Yang @ May 24, 2023.
*/
#define ENTRY_POINT 0x1000
#define DEFAULT_INSPECT_TEXT_SIZE   512
#define DEFAULT_INSPECT_STACK_SIZE  256
#define DEFAULT_STACK_SIZE  64*1024

/* Do endian transfer to make it easy to be compared with section .text */
unsigned trans(unsigned i)
{
  unsigned a = (i & 0xff000000)>>24;
  unsigned b = (i & 0x00ff0000)>>16;
  unsigned c = (i & 0x0000ff00)>>8;
  unsigned d = (i & 0x000000ff);
  return (d<<24 | c <<16 | b<<8 | a);
}

int hello(unsigned long * args)
{  
  /** add a more complete lib & interface in future. 
   *  now we call eapp_call directly
   */
  char *elf_file_name = "/root/case-inspectee";
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

  eapp_print("[pe] request_arg [%p], inspect_arg [%p].\n",
              (void *)(&request_param), (void *)(&inspect_request_param));
  retval = eapp_run_enclave((unsigned long)(&run_param));

  unsigned loop = 0;
  while (retval == 0)
  {
    if (loop == 0)
    {
      /* dump code from 0x1000 to 0x1200 */
      inspect_param.dump_context = 0;
      inspect_param.inspect_eid = run_param.run_eid;
      inspect_param.inspect_address = ENTRY_POINT;
      inspect_param.inspect_size = DEFAULT_INSPECT_TEXT_SIZE;
      eapp_inspect_enclave((unsigned long)(&inspect_param));
      eapp_print("[pe] [inspector] section .text from [%lx] to [%lx].\n", ENTRY_POINT, ENTRY_POINT+DEFAULT_INSPECT_TEXT_SIZE);
      unsigned *instruction_ptr = (unsigned *)content;
      while (instruction_ptr < content + DEFAULT_INSPECT_TEXT_SIZE)
      {
        unsigned instruction0 = (unsigned)(*(instruction_ptr));
        unsigned instruction1 = (unsigned)(*(instruction_ptr+1));
        unsigned instruction2 = (unsigned)(*(instruction_ptr+2));
        unsigned instruction3 = (unsigned)(*(instruction_ptr+3));
        eapp_print("|%x|%x|%x|%x|\n", 
          trans(instruction0), trans(instruction1), trans(instruction2), trans(instruction3));
        instruction_ptr += 4;
      }
      /* todo. add a compare check here. */
    }
    else if (loop == 1)
    {
      /* dump context */
      inspect_param.dump_context = 1;
      eapp_inspect_enclave((unsigned long)(&inspect_param));
      dump_context = (ocall_request_dump_t *)content;
      eapp_print("%lx | %lx \n", dump_context->encl_ptbr, dump_context->state.sp);
    }
    loop++;
    requested = 0;
    switch (return_reason)
    {
      case NE_REQUEST_INSPECT:
        requested = 1;
        int inspect_size_int = inspect_request_param.inspect_size;
        eapp_print("[pe] [inspector] receive NE_REQUEST_INSPECT with ptr [%lx] and size [%d]\n", 
                    inspect_request_param.inspect_ptr, inspect_size_int);
        /* We do live variable inspection first. */
        inspect_param.dump_context = 0;
        inspect_param.inspect_eid = run_param.run_eid;
        inspect_param.inspect_address = inspect_request_param.inspect_ptr;
        inspect_param.inspect_size = inspect_request_param.inspect_size;
        eapp_inspect_enclave((unsigned long)(&inspect_param));
        unsigned long *selector_ptr = (unsigned long *)content;
        eapp_print("[pe] [inspector] NE's selector value: [%lx]", *selector_ptr);

        /* We then do stack check to find out detailed problem. */
        inspect_param.dump_context = 1;
        eapp_inspect_enclave((unsigned long)(&inspect_param));
        dump_context = (ocall_request_dump_t *)content;
        // eapp_print("[pe] [inspector] CSR_MEPC: [%lx] | x[sp]: [%lx]\n", dump_context->mepc, dump_context->state.sp);

        inspect_param.dump_context = 0;
        inspect_param.inspect_address = dump_context->state.sp;
        inspect_param.inspect_size = DEFAULT_INSPECT_STACK_SIZE;
        eapp_inspect_enclave((unsigned long)(&inspect_param));
        eapp_print("[pe] [inspector] Data on stack from [%lx] to [%lx].\n", inspect_param.inspect_address, inspect_param.inspect_address+DEFAULT_INSPECT_STACK_SIZE);
        unsigned *data_ptr = (unsigned *)content;
        while (data_ptr < content + DEFAULT_INSPECT_STACK_SIZE)
        {
          unsigned data0 = (unsigned)(*(data_ptr));
          unsigned data1 = (unsigned)(*(data_ptr+1));
          unsigned data2 = (unsigned)(*(data_ptr+2));
          unsigned data3 = (unsigned)(*(data_ptr+3));
          eapp_print("|%x|%x|%x|%x|\n", 
            trans(data0), trans(data1), trans(data2), trans(data3));
          data_ptr += 4;
        }
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

  /* exit successfully */
  eapp_print("[pe] [inspector] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
