/**
 * This program is a Privileged Enclave demo in Memory Sharing case study, 
 * which supports two Normal Enclave execute interleavingly, 
 *    supports Memory Sharing Functionality between them,
 *    and exits to host if both Normal Enclave have exited.
 * In this case study, 
 *    sharer/sender (case-sharer) will set one private page as public (ONLY for its PE and other peer NE),
 *    sharee/recver (case-sharee) will acquire this page and read it. 
 *  by Ganxiang Yang @ May 22, 2023.
*/
#include "eapp.h"
#include "print.h"
#include "privil.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#define DEFAULT_STACK_SIZE  64*1024
#define NE_NUMBER 2

int ne_scheduler(int prev)
{
  return prev ? 0 : 1;
}
int hello(unsigned long * args)
{
  // selector: 0: sender; 1: recver.
  int retval = 0, requested = 0, i = 0, single_thread = 0, prev = 0;
  char *elf_file_names[NE_NUMBER] = {"/root/case-sharer", "/root/case-sharee"};
  ocall_create_param_t create_params[NE_NUMBER];
  for (i = 0 ; i < NE_NUMBER ; i++)
  { 
    create_params[i].elf_file_ptr = (unsigned long)(&(create_params[i]));
    create_params[i].encl_type = NORMAL_ENCLAVE;
    create_params[i].stack_size = DEFAULT_STACK_SIZE;
    /* disable shm currently */
    create_params[i].shmid = 0;
    create_params[i].shm_offset = 0;
    create_params[i].shm_size = 0;
    memcpy(create_params[i].elf_file_name, elf_file_names[i], ELF_FILE_LEN);
    retval = eapp_create_enclave((unsigned long)(&(create_params[i])));
    if (retval)
    {
      eapp_print("eapp_create_enclave failed: %d\n",retval);
    }
    eapp_print("Allocated [%d]-th NORMAL ENCLAVE eid: [%d]\n", i, create_params[i].eid);
  }
  int return_reasons[NE_NUMBER], return_values[NE_NUMBER];
  ocall_run_param_t run_params[NE_NUMBER];
  ocall_request_t request_params[NE_NUMBER];
  for (i = 0; i < NE_NUMBER ; i++)
  {
    run_params[i].run_eid = create_params[i].eid;
    run_params[i].reason_ptr = (unsigned long)(&(return_reasons[i]));
    run_params[i].retval_ptr = (unsigned long)(&(return_values[i]));
    run_params[i].request_arg = (unsigned long)(&(request_params[i]));
  }

  int init_run[NE_NUMBER];
  memset(init_run, 0, NE_NUMBER*sizeof(int));

  /* build a better scheduler in future */
  /* i: next run NE. prev: previous run NE. */
  i = 0;
  while (retval == 0)
  {
    requested = 0;
    if (!init_run[i])
    {
      retval = eapp_run_enclave((unsigned long)(&(run_params[i])));
      init_run[i] = 1;
      if (retval)
      {
        eapp_print("[pe] eapp_run_enclave non-zero [%d]\n", retval);
        break;
      }
    }
    prev = i;
    
    if (return_reasons[prev] == RETURN_USER_EXIT_ENCL)
    {
      /* print here. */
      if (single_thread)
        break;
      else 
      {
        i = ne_scheduler(prev);
        single_thread = 1;
      }
    }

    switch (return_reasons[prev])
    {
      case NE_REQUEST_SHARE_PAGE:
        requested = 1;
        /* todo. */
        break;
      default:
        break;
    }

    // save previous NE pause reason.
    run_params[prev].resume_reason = return_reasons[prev];
    if (requested)
    {
      run_params[prev].resume_reason = RETURN_USER_NE_REQUEST;
    }

    // select next running enclave.
    if (!single_thread)
      i = ne_scheduler(prev);
    
    retval = eapp_resume_enclave((unsigned long)(&(run_params[i])));
  }
  eapp_print("[pe] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
