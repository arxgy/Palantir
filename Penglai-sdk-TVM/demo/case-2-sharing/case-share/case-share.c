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
/* too large SHARE_LIMIT cause mmap error, out-of-scope */
#define SHARE_LIMIT 1 << 4
/* A better allocation method is required. */
typedef struct share_record
{
  int eid;  // idr-layer, owner of the page.
  int share_id;
  unsigned long vaddr;
  unsigned long size;
} share_record_t;


int ne_scheduler(int prev)
{
  return prev ? 0 : 1;
}

int share_id_alloc(int *prev)
{
  return ++(*prev);
}

int hello(unsigned long * args)
{
  int retval = 0, prev = 0;
  int requested = 0, i = 0, single_thread = 0, thread_init = 0;

  char *elf_file_names[NE_NUMBER] = {"/root/case-sharer", "/root/case-sharee"};
  int share_id_counts[NE_NUMBER];
  memset(share_id_counts, 0, sizeof(int)*NE_NUMBER);
  share_record_t share_records[SHARE_LIMIT];
  memset(share_records, 0, SHARE_LIMIT*sizeof(share_record_t));
  int share_record_count = 0;

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
    share_id_counts[i] = 0;
  }
  int return_reasons[NE_NUMBER], return_values[NE_NUMBER];
  ocall_run_param_t run_params[NE_NUMBER];
  ocall_request_t request_params[NE_NUMBER];
  ocall_response_t response_params[NE_NUMBER];
  ocall_request_inspect_t inspect_params[NE_NUMBER];
  ocall_request_share_t share_params[NE_NUMBER];

  ocall_response_share_t share_responses[NE_NUMBER];
  /* This variable is used for do memory introspection by PE. */
  ocall_inspect_param_t ocall_inspect_param_local;
  char *inspect_content = (char *)eapp_mmap(NULL, PAGE_SIZE);
  // char inspect_content[PAGE_SIZE];
  memset(inspect_content, 0, PAGE_SIZE);
  ocall_inspect_param_local.inspect_result = (unsigned long)(inspect_content);

  for (i = 0; i < NE_NUMBER ; i++)
  {
    run_params[i].run_eid = create_params[i].eid;
    run_params[i].reason_ptr = (unsigned long)(&(return_reasons[i]));
    run_params[i].retval_ptr = (unsigned long)(&(return_values[i]));
    run_params[i].request_arg = (unsigned long)(&(request_params[i]));
    run_params[i].response_arg = (unsigned long)(&(response_params[i]));

    request_params[i].inspect_request = (unsigned long)(&(inspect_params[i]));
    request_params[i].share_page_request = (unsigned long)(&(share_params[i]));
    response_params[i].inspect_response = NULL;
    response_params[i].share_page_response = (unsigned long)(&(share_responses[i]));
    eapp_print("[pe] thread [%lx]: response_arg[%lx], share_page_response[%lx]\n",
                i, (unsigned long)(&(response_params[i])), (unsigned long)(&(share_responses[i])));
  }

  int init_run[NE_NUMBER];
  memset(init_run, 0, NE_NUMBER*sizeof(int));

  /* todo. build a better scheduler for [#thread > 2] in future */
  i = 0;
  while (retval == 0)
  {
    thread_init = 0;
    requested = 0;
    if (!init_run[i])
    {
      retval = eapp_run_enclave((unsigned long)(&(run_params[i])));
      thread_init = 1;
      init_run[i] = 1;
      if (retval)
      {
        eapp_print("[pe] eapp_run_enclave non-zero [%d]\n", retval);
        break;
      }
    }
    prev = i;
    eapp_print("[pe] previous run thread: %d\n", prev);
    if (return_reasons[prev] == RETURN_USER_EXIT_ENCL)
    {
      eapp_print("[pe] thread: %d exit!\n", prev);
      /* print here. */
      if (single_thread)
        break;
      else 
      {
        i = ne_scheduler(prev);
        single_thread = 1;
      }
    }
    /* set default value. */
    response_params[prev].request = 0;
    switch (return_reasons[prev])
    {
      case NE_REQUEST_INSPECT:
        /* We don't perform any service in this case study. */
        break;
      case NE_REQUEST_SHARE_PAGE:
        /* NE provides vaddr & size */
        requested = 1;
        /* complete the share_param and display */
        share_params[prev].eid = create_params[prev].eid;
        share_params[prev].share_id = share_id_alloc((int *)(&(share_id_counts[prev])));
        int share_size_int = share_params[prev].share_size;
        int share_eid_int = share_params[prev].eid;
        int share_id_int = share_params[prev].share_id;
        eapp_print("[pe] receive [%d] NE_REQUEST_SHARE_PAGE with ptr [%lx] and size [%d]. Alloc page [%d]\n", 
                    share_eid_int,
                    share_params[prev].share_content_ptr, 
                    share_params[prev].share_size, 
                    share_id_int);
        /* add/copy the share page message to record */
        share_records[share_record_count].eid = share_params[prev].eid;
        share_records[share_record_count].share_id = share_params[prev].share_id;
        share_records[share_record_count].vaddr = share_params[prev].share_content_ptr;
        share_records[share_record_count].size = share_params[prev].share_size;
        ++share_record_count;
        break;
      case NE_REQUEST_ACQUIRE_PAGE:
        /* NE provides eid & share_id & content_ptr & size */
        requested = 1;
        /* todo. */
        eapp_print("[sm] NE_REQUEST_ACQUIRE_PAGE: target eid [%lx], share_id [%lx].\n", 
                    share_params[prev].eid,
                    share_params[prev].share_id);
        int iter = 0, found = 0, share_idx = 0;
        for (iter = 0; iter < SHARE_LIMIT ; iter++)
        {
          if (share_records[iter].eid == share_params[prev].eid && 
              share_records[iter].share_id == share_params[prev].share_id)
          {
            share_idx = iter;
            found = 1;
            break;
          }
        }
        if (!found)
          eapp_print("[pe] [ERROR] cannot find target shared page.\n");
        /* fill inspect param, do inspection */
        /* This check might be redundant */
        int eid_int = share_params[prev].eid;
        eapp_print("[pe] share_params[prev].eid: [%d]", eid_int);
        found = 0;
        for (iter = 0; iter < NE_NUMBER ; iter++)
        {
          eid_int = create_params[iter].eid;
          eapp_print("[pe] create_params[%d].eid: [%d].\n", iter, eid_int);
          if (create_params[iter].eid == share_params[prev].eid)
          {
            found = 1;
            break;
          }
        }
        if (!found)
          eapp_print("[pe] [ERROR] cannot find target peer Normal Enclave.\n");
        ocall_inspect_param_local.inspect_eid = share_params[prev].eid;
        ocall_inspect_param_local.inspect_address = share_records[share_idx].vaddr;
        ocall_inspect_param_local.inspect_size = share_records[share_idx].size;
        eapp_inspect_enclave((unsigned long)(&ocall_inspect_param_local));
        eapp_print("%s", inspect_content);
        /* pass result back. */
        response_params[prev].request = NE_REQUEST_ACQUIRE_PAGE;
        share_responses[prev].src_ptr = (unsigned long)(inspect_content);
        share_responses[prev].dest_ptr = share_params[prev].share_content_ptr;
        share_responses[prev].share_size = share_params[prev].share_size;
        eapp_print("[pe] prev [%lx], response_arg (VA)[%lx], response_request [%lx], share_page_response (VA)[%lx].\n", 
                    prev,
                    run_params[prev].response_arg, 
                    response_params[prev].request, 
                    response_params[prev].share_page_response);
        eapp_print("[pe] prev [%lx], share src (VA)[%lx], share dest [%lx], share_size [%lx]\n", 
                    prev,
                    share_responses[prev].src_ptr, 
                    share_responses[prev].dest_ptr, 
                    share_responses[prev].share_size);
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
    
    if (thread_init)
      continue;
    eapp_print("[pe] resume to execute thread %lx.\n", i);
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
