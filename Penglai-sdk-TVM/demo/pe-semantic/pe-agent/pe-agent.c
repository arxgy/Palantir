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

int test_attest(unsigned long *args)
{
  return 0;
}

int test_create(unsigned long *args)
{
  return 0;
}

int test_destroy(unsigned long *args)
{
  return 0;
}

int test_pressure(unsigned long *args)
{
  return 0;
}

int test_resume(unsigned long *args)
{
  return 0;
}

int test_run(unsigned long *args)
{
  return 0;
}

int hello(unsigned long * args)
{  
  /** add a more complete lib & interface in future. 
   *  now we call eapp_call directly
   */
  char *elf_file_name = "/root/ne-hello";
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
  eapp_print("Allocated PRIVIL ENCLAVE eid: [%d]\n", eid);

  memcpy(create_param.elf_file_name, elf_file_name, ELF_FILE_LEN);  
  int retval = eapp_create_enclave((unsigned long)(&create_param));
  if (retval)
  {
    eapp_print("eapp_create_enclave failed: %d\n",retval);
  }
  eapp_print("Allocated NORMAL ENCLAVE eid: [%d]\n", create_param.eid);
  

  struct report_t report;
  ocall_attest_param_t attest_param;
  attest_param.attest_eid = create_param.eid;
  attest_param.isShadow = 0;
  attest_param.nonce = 4096;
  attest_param.report_ptr = (unsigned long)(&report);
  memset(&report, 0, sizeof(struct report_t));
  eapp_print("[pe] report vaddr: [%p]", &report);
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
    // eapp_print("%d|", sum);
  }
  eapp_print("\n[pe] attestation sum: %d", sum);

  ocall_run_param_t run_param;
  int return_reason, return_value;
  run_param.run_eid = create_param.eid;
  run_param.reason_ptr = &return_reason;
  run_param.retval_ptr = &return_value;

  retval = eapp_run_enclave((unsigned long)(&run_param));

  int stop_and_destroy = 0;
  
  /* todo. ADD A SCHEDULER HERE. */
  while (retval == 0)
  {
    // eapp_print("[pe] eapp_run_enclave return_reason: [%d]\n", return_reason);
    switch (return_reason)
    {
      case RETURN_USER_EXIT_ENCL:
        // eapp_print("[pe] Normal Enclave Exit!\n");
        break;
      case RETURN_USER_NE_IRQ:
        // eapp_print("[pe] run return for RETURN_USER_NE_IRQ\n");
        break;
      default:
        // eapp_print("[pe] eapp_run_enclave return value is: [%d]\n", return_reason);
        break;
    }
    if (return_reason == RETURN_USER_EXIT_ENCL)
    {
      eapp_print("[pe] eapp_run_enclave return_value: [%d]\n", return_value);
      break;
    }
    // eapp_print("[pe] eapp_run_enclave return_reason: [%d]\n", return_reason);
    // eapp_print("[pe] try resume NE [%d]\n", run_param.run_eid);
    /* we reuse the [return reason] as [resume reason] */
    if (stop_and_destroy)
    {
      // retval = eapp_stop_enclave((unsigned long)(&stop_param));
      // eapp_print("[pe] eapp_stop_enclave return value is [%d]\n", retval);
      retval = eapp_destroy_enclave(run_param.run_eid);
      eapp_print("[pe] eapp_destroy_enclave return value is [%d]\n", retval);
      break;
    }
    else 
    {
      run_param.resume_reason = return_reason;
      retval = eapp_resume_enclave((unsigned long)(&run_param));
    }
  }

  /* exit successfully */
  eapp_print("[pe] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}