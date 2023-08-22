/**
 * This program is a Privileged Enclave demo in Live Enclave Migration case study (local ver),
 * which will 
 *  1. stoppped the Normal Enclave, dump files
 *  2. restore the Normal Enclave from given dump files, implement Live Migration.
 *  by Anonymous Author @ May 25, 2023.
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
#define DEFAULT_STACK_BASE 0x3800000000
#define DEFAULT_INSPECT_TEXT_SIZE   512
#define DEFAULT_INSPECT_STACK_SIZE  256
#define DEFAULT_STACK_SIZE  64*1024
#define DEFAULT_REGS_NUM  39

#define MMAP_SIZE PAGE_SIZE<<1

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

void insert_mem_area(snapshot_mem_area_t *area, unsigned long vaddr, unsigned long start)
{
  area->vaddr = vaddr;
  area->start = start;
}


int hello(unsigned long * args)
{  
  /* migration = RECV + LOAD + DESTROY + CREATE */
  unsigned long begin_cycle, end_cycle;
  unsigned long load_begin, load_end;
  unsigned long destroy_begin, destroy_end;
  unsigned long create_begin, create_end;
  int total_pages;

  char *elf_file_name = "/root/eval-migratee";
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
  begin_cycle = get_cycle();
  int retval = eapp_create_enclave((unsigned long)(&create_param));
  end_cycle = get_cycle();
  eapp_print("[pe] [eval-migrator] initial create cycle cost: [%lx]\n", (end_cycle-begin_cycle));

  if (retval)
  {
    eapp_print("eapp_create_enclave failed: %d\n",retval);
  }
  

  ocall_request_t request_param;
  ocall_response_t response_param;
  ocall_request_inspect_t inspect_request_param;
  request_param.inspect_request = (unsigned long)(&inspect_request_param);
  response_param.inspect_response = NULL;
  response_param.share_page_response = NULL;

  ocall_run_param_t run_param;
  int return_reason, return_value;
  run_param.run_eid = create_param.eid;
  run_param.reason_ptr = (unsigned long)(&return_reason);
  run_param.retval_ptr = (unsigned long)(&return_value);
  run_param.request_arg = (unsigned long)(&request_param);
  run_param.response_arg = (unsigned long)(&response_param);

  ocall_inspect_param_t inspect_param;
  retval = eapp_run_enclave((unsigned long)(&run_param));
  begin_cycle = get_cycle();  // mark recv time
  char dump_mems[PAGE_SIZE];       // for mem
  ocall_request_dump_t dump_regs;  // for regs
  enclave_mem_dump_t dump_vmas;    // for vma
  snapshot_state_t state;

  memset((void *)(&dump_vmas), 0, sizeof(enclave_mem_dump_t));
  memset((void *)dump_mems, 0, PAGE_SIZE);
  memset((void *)(&dump_regs), 0, sizeof(ocall_request_dump_t));
  memset((void *)(&state), 0, sizeof(snapshot_state_t));
  
  /* We set parameters carefully to ensure sizeof <= 4kB */
  int requested;
  while (retval == 0)
  {
    requested = 0;
    switch (return_reason)
    { 
      case NE_REQUEST_DEBUG_PRINT:
        load_begin = get_cycle();
        requested = 1;
        int i;
        inspect_param.inspect_eid = run_param.run_eid;
        /* dump vma */
        inspect_param.dump_context = INSPECT_VMA;
        inspect_param.inspect_result = (unsigned long)(&dump_vmas);
        eapp_inspect_enclave((unsigned long)(&inspect_param));
        total_pages++;
        /* dump regs */
        inspect_param.dump_context = INSPECT_REGS;
        inspect_param.inspect_result = (unsigned long)(&dump_regs);
        eapp_inspect_enclave((unsigned long)(&inspect_param));
        total_pages++;

        inspect_param.dump_context = INSPECT_MEM;
        inspect_param.inspect_result = (unsigned long)(dump_mems);
        unsigned long sp = dump_regs.state.sp;
        unsigned long copy_cur;
        void *copy_dest;

        /* copy registers */
        state.regs = dump_regs;
        /* copy stacks */
        inspect_param.inspect_size = PAGE_SIZE;
        
        copy_cur = DEFAULT_STACK_BASE - PAGE_SIZE;
        while (1)
        {
          inspect_param.inspect_address = copy_cur;
          eapp_inspect_enclave((unsigned long)(&inspect_param));
          total_pages++;
          copy_dest = eapp_mmap(NULL, MMAP_SIZE);
          memcpy(copy_dest, (void *)dump_mems, PAGE_SIZE);
          /* print stack */
          state.stack[state.stack_sz++] = (unsigned long)(copy_dest);
          if (copy_cur <= sp)
            break;
          copy_cur -= PAGE_SIZE;
        }

        /* Currently, seems mmap and heap are both page-grained. */
        vm_area_dump_t vma;
        snapshot_mem_area_t *mem_area;
        /* copy mmap */
        snapshot_mmap_state_t *mmap = &(state.mmap); 
        for (i = 0 ; i < dump_vmas.mmap_sz ; i++)
        {
          vma = dump_vmas.mmap_vma[i];
          copy_cur = vma.va_start;
          while (copy_cur+PAGE_SIZE < vma.va_end)
          {
            inspect_param.inspect_address = copy_cur;
            eapp_inspect_enclave((unsigned long)(&inspect_param));
            total_pages++;
            copy_dest = eapp_mmap(NULL, MMAP_SIZE);
            memcpy(copy_dest, (void *)dump_mems, PAGE_SIZE);
            mem_area = &(mmap->mmap_areas[mmap->mmap_sz++]);
            insert_mem_area(mem_area, (unsigned long)copy_dest, copy_cur);
            copy_cur += PAGE_SIZE;
          }
          inspect_param.inspect_address = copy_cur;
          inspect_param.inspect_size = vma.va_end - copy_cur;
          eapp_inspect_enclave((unsigned long)(&inspect_param));
          total_pages++;
          copy_dest = eapp_mmap(NULL, MMAP_SIZE);
          memcpy(copy_dest, (void *)dump_mems, inspect_param.inspect_size);
          mem_area = &(mmap->mmap_areas[mmap->mmap_sz++]);
          insert_mem_area(mem_area, (unsigned long)copy_dest, copy_cur);
        }
        /* copy heap */
        snapshot_heap_state_t *heap = &(state.heap);
        for (i = 0 ; i < dump_vmas.heap_sz ; i++)
        {
          vma = dump_vmas.heap_vma[i];
          copy_cur = vma.va_start;
          while (copy_cur+PAGE_SIZE < vma.va_end)
          {
            inspect_param.inspect_address = copy_cur;
            eapp_inspect_enclave((unsigned long)(&inspect_param));
            total_pages++;
            copy_dest = eapp_mmap(NULL, MMAP_SIZE);
            memcpy(copy_dest, (void *)dump_mems, PAGE_SIZE);
            mem_area = &(heap->heap_areas[heap->heap_sz++]);
            insert_mem_area(mem_area, (unsigned long)copy_dest, copy_cur);
            copy_cur += PAGE_SIZE;
          }
          inspect_param.inspect_address = copy_cur;
          inspect_param.inspect_size = vma.va_end - copy_cur;
          eapp_inspect_enclave((unsigned long)(&inspect_param));
          total_pages++;
          copy_dest = eapp_mmap(NULL, MMAP_SIZE);
          memcpy(copy_dest, (void *)dump_mems, inspect_param.inspect_size);
          mem_area = &(heap->heap_areas[heap->heap_sz++]);
          insert_mem_area(mem_area, (unsigned long)copy_dest, copy_cur);
        }
        load_end = get_cycle();
        ocall_destroy_param_t destroy_param;
        destroy_param.destroy_eid = run_param.run_eid;
        destroy_begin = get_cycle();
        retval = eapp_destroy_enclave((unsigned long)(&destroy_param));
        destroy_end = get_cycle();
        goto migrate;
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
      eapp_print("[pe] [inspector] eapp_run_enclave return_value non-zero: [%d]\n", return_value);
      break;
    }
    run_param.resume_reason = return_reason;
    // For all request-interrupt, we provide a uniformed resume reason.
    if (requested)
    {
      run_param.resume_reason = RETURN_USER_NE_REQUEST;        
    }
    retval = eapp_resume_enclave((unsigned long)(&run_param));
    begin_cycle = get_cycle(); // mark recv time
  }

migrate:
  /* create/restore Normal Enclave from (vma) dump struct (locally). */
  create_param.migrate_arg = (unsigned long)(&state);
  create_begin = get_cycle();
  retval = eapp_create_enclave((unsigned long)(&create_param));
  create_end = get_cycle();
  end_cycle = create_end;

  eapp_print("[pe] [eval-migrator] #PAGE: [%d]\n", total_pages);
  eapp_print("[pe] [eval-migrator] total cost: [%lx]", (end_cycle-begin_cycle));
  eapp_print("[pe] [eval-migrator] load cost: [%lx]", (load_end-load_begin));
  eapp_print("[pe] [eval-migrator] destroy cost: [%lx]", (destroy_end-destroy_begin));
  eapp_print("[pe] [eval-migrator] create cost: [%lx]", (create_end-create_begin));


  if (retval)
  {
    eapp_print("[pe] eapp_create_enclave [migrate] failed: %d\n",retval);
  }

  /* run migrated enclave */
  run_param.run_eid = create_param.eid;
  retval = eapp_run_enclave((unsigned long)(&run_param));
  while (retval == 0)
  {
    requested = 0;
    switch (return_reason)
    {
    case NE_REQUEST_DEBUG_PRINT:
      requested = 1;
      break;
    default:
      break;
    }
    if (return_reason == RETURN_USER_EXIT_ENCL)
    {
      eapp_print("[pe] [migrator] eapp_run_enclave return_value: [%d]\n", return_value);
      break;
    }
    if (retval)
    {
      eapp_print("[pe] [migrator] eapp_run_enclave return_value non-zero: [%d]\n", return_value);
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
  eapp_print("[pe] [migrator] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
