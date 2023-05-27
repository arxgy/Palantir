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
#define DEFAULT_STACK_BASE 0x3800000000
#define DEFAULT_INSPECT_TEXT_SIZE   512
#define DEFAULT_INSPECT_STACK_SIZE  256
#define DEFAULT_STACK_SIZE  64*1024
#define DEFAULT_REGS_NUM  39

#define DEFAULT_SNAPSHOT_STAGE  15
#define MMAP_SIZE PAGE_SIZE<<1
/* Do endian transfer to make it easy to be compared with section .text */
unsigned trans(unsigned i)
{
  unsigned a = (i & 0xff000000)>>24;
  unsigned b = (i & 0x00ff0000)>>16;
  unsigned c = (i & 0x0000ff00)>>8;
  unsigned d = (i & 0x000000ff);
  return (d<<24 | c <<16 | b<<8 | a);
}

/* tools for print memory region */
void printm(unsigned long start, unsigned long size)
{
  unsigned *instruction_ptr = (unsigned *)start;
  while (instruction_ptr < start + size)
  {
    unsigned instruction0 = (unsigned)(*(instruction_ptr));
    unsigned instruction1 = (unsigned)(*(instruction_ptr+1));
    unsigned instruction2 = (unsigned)(*(instruction_ptr+2));
    unsigned instruction3 = (unsigned)(*(instruction_ptr+3));
    unsigned instruction4 = (unsigned)(*(instruction_ptr+4));
    unsigned instruction5 = (unsigned)(*(instruction_ptr+5));
    unsigned instruction6 = (unsigned)(*(instruction_ptr+6));
    unsigned instruction7 = (unsigned)(*(instruction_ptr+7));
    eapp_print("|%x|%x|%x|%x|%x|%x|%x|%x|\n", 
      trans(instruction0), trans(instruction1), trans(instruction2), trans(instruction3),
      trans(instruction4), trans(instruction5), trans(instruction6), trans(instruction7));
    instruction_ptr += 8;
  }
}

void printr(ocall_request_dump_t *regs)
{
  unsigned long *regs_entry = (unsigned long *)(regs);
  int i = 0;
  for (i = 0 ; i < DEFAULT_REGS_NUM ; i++)
  {
    eapp_print("x[%d]: [%lx]\n", i, *regs_entry);
    regs_entry++;
  }
}

void insert_mem_area(snapshot_mem_area_t *area, unsigned long vaddr, unsigned long start)
{
  area->vaddr = vaddr;
  area->start = start;
}


int hello(unsigned long * args)
{  
  char *elf_file_name = "/root/case-migratee";
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

  ocall_run_param_t run_param;
  int return_reason, return_value;
  run_param.run_eid = create_param.eid;
  run_param.reason_ptr = (unsigned long)(&return_reason);
  run_param.retval_ptr = (unsigned long)(&return_value);
  run_param.request_arg = (unsigned long)(&request_param);
  run_param.response_arg = (unsigned long)(&response_param);

  ocall_inspect_param_t inspect_param;
  eapp_print("[pe] request_arg [%p], inspect_arg [%p].\n",
              (void *)(&request_param), (void *)(&inspect_request_param));
  retval = eapp_run_enclave((unsigned long)(&run_param));

  char dump_mems[PAGE_SIZE];        // for mem
  ocall_request_dump_t dump_regs; // for regs
  enclave_mem_dump_t dump_vmas;    // for vma
  snapshot_state_t state;

  memset((void *)(&dump_vmas), 0, sizeof(enclave_mem_dump_t));
  memset((void *)dump_mems, 0, PAGE_SIZE);
  memset((void *)(&dump_regs), 0, sizeof(ocall_request_dump_t));
  memset((void *)(&state), 0, sizeof(snapshot_state_t));
  
  /* We set parameters carefully to ensure sizeof <= 4kB */
  eapp_print("[pe] enclave_mem_dump_t size: [%lx]\n", sizeof(enclave_mem_dump_t));
  eapp_print("[pe] snapshot_state_t size: [%lx]\n", sizeof(snapshot_state_t));

  unsigned loop = 0;
  while (retval == 0)
  {
    if (loop == DEFAULT_SNAPSHOT_STAGE)
    {
      int i;
      inspect_param.inspect_eid = run_param.run_eid;
      /* dump vma */
      inspect_param.dump_context = INSPECT_VMA;
      inspect_param.inspect_result = (unsigned long)(&dump_vmas);
      eapp_inspect_enclave((unsigned long)(&inspect_param));
      for (i = 0 ; i < dump_vmas.heap_sz ; i++)
        eapp_print("[pe] heap_vma[%d]: start: [%lx], end: [%lx]\n", i, dump_vmas.heap_vma[i].va_start, dump_vmas.heap_vma[i].va_end);
      for (i = 0 ; i < dump_vmas.mmap_sz ; i++)
        eapp_print("[pe] mmap_vma[%d]: start: [%lx], end: [%lx]\n", i, dump_vmas.mmap_vma[i].va_start, dump_vmas.mmap_vma[i].va_end);
      /* dump regs */
      inspect_param.dump_context = INSPECT_REGS;
      inspect_param.inspect_result = (unsigned long)(&dump_regs);
      eapp_inspect_enclave((unsigned long)(&inspect_param));
      eapp_print("[pe] CSR_MEPC [%lx], x[sp] [%lx]\n", dump_regs.mepc, dump_regs.state.sp);
      printr(&dump_regs);

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

        copy_dest = eapp_mmap(NULL, MMAP_SIZE);
        memcpy(copy_dest, (void *)dump_mems, PAGE_SIZE);
        /* print stack */
        // printm(copy_dest, PAGE_SIZE);
        state.stack[state.stack_sz++] = (unsigned long)(copy_dest);
        eapp_print("[pe] [migrator] stack addr: [%lx]\n", (unsigned long)(copy_dest));
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
          copy_dest = eapp_mmap(NULL, MMAP_SIZE);
          memcpy(copy_dest, (void *)dump_mems, PAGE_SIZE);
          mem_area = &(mmap->mmap_areas[mmap->mmap_sz++]);
          insert_mem_area(mem_area, (unsigned long)copy_dest, copy_cur);
          copy_cur += PAGE_SIZE;
        }
        inspect_param.inspect_address = copy_cur;
        inspect_param.inspect_size = vma.va_end - copy_cur;
        eapp_inspect_enclave((unsigned long)(&inspect_param));
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
          copy_dest = eapp_mmap(NULL, MMAP_SIZE);
          memcpy(copy_dest, (void *)dump_mems, PAGE_SIZE);
          mem_area = &(heap->heap_areas[heap->heap_sz++]);
          insert_mem_area(mem_area, (unsigned long)copy_dest, copy_cur);
          copy_cur += PAGE_SIZE;
        }
        inspect_param.inspect_address = copy_cur;
        inspect_param.inspect_size = vma.va_end - copy_cur;
        eapp_inspect_enclave((unsigned long)(&inspect_param));
        copy_dest = eapp_mmap(NULL, MMAP_SIZE);
        memcpy(copy_dest, (void *)dump_mems, inspect_param.inspect_size);
        mem_area = &(heap->heap_areas[heap->heap_sz++]);
        insert_mem_area(mem_area, (unsigned long)copy_dest, copy_cur);
      }
      /* check */
      for (i = 0 ; i < mmap->mmap_sz ; i++)
      {
        eapp_print("[pe] mmap_area[%d]: vaddr [%lx], start [%lx]\n",
                    i, mmap->mmap_areas[i].vaddr, mmap->mmap_areas[i].start);
      }
      for (i = 0 ; i < heap->heap_sz ; i++)
      {
        eapp_print("[pe] heap_area[%d]: vaddr [%lx], start [%lx]\n",
                    i, heap->heap_areas[i].vaddr, heap->heap_areas[i].start);
      }
      /* destroy stopped enclave. */
      ocall_destroy_param_t destroy_param;
      destroy_param.destroy_eid = run_param.run_eid;
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
  }

  /* create/restore Normal Enclave from (vma) dump struct (locally). */
  create_param.migrate_arg = (unsigned long)(&state);
  eapp_print("[pe] start migration from state at [%p]", (void *)(&state));
  retval = eapp_create_enclave((unsigned long)(&create_param));
  if (retval)
  {
    eapp_print("[pe] eapp_create_enclave [migrate] failed: %d\n",retval);
  }

  eapp_print("[pe] [migrator] Allocated [migrate] NORMAL ENCLAVE eid: [%d]\n", create_param.eid);
  /* stack check passed. */
  /* regs check passed */
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
