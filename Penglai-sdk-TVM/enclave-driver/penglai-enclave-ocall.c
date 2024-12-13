#include "penglai-enclave-ocall.h"
#include "penglai-enclave-ioctl.h"
#include "penglai-enclave-driver.h"
#include "penglai-shm.h"
#include "penglai-schrodinger.h"
#include "penglai-enclave-persistency.h"
#include "penglai-enclave-ocall.h"
#include "penglai-enclave.h"
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/err.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <asm/uaccess.h>

int handle_ocall_mmap(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  uintptr_t order, vaddr;
  int ret;
  if(isShadow)
    order = ilog2((enclave_instance->ocall_arg1 >> RISCV_PGSHIFT) - 1) + 1;
  else
    order = ilog2((enclave->ocall_arg1 >> RISCV_PGSHIFT) - 1) + 1;
  vaddr = penglai_get_free_pages(GFP_KERNEL, order);
  if(!vaddr)
  {
    ret = -1;
    penglai_eprintf("penglai_enclave_ocall: OCALL_MMAP  is failed\r\n");
    return ret;
  }
  ret = SBI_PENGLAI_5(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_MMAP, __pa(vaddr), (1<<order)*RISCV_PGSIZE);
  return ret;
}

int handle_ocall_munmap(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  uintptr_t vaddr, order;
  int ret;
  if(isShadow)
  {
    vaddr = (uintptr_t)__va(enclave_instance->ocall_arg0);
    order = ilog2((enclave_instance->ocall_arg1 >> RISCV_PGSHIFT) - 1) + 1;
  }
  else
  {
    vaddr = (uintptr_t)__va(enclave->ocall_arg0);
    order = ilog2((enclave->ocall_arg1 >> RISCV_PGSHIFT) - 1) + 1;
  }
  
  free_pages(vaddr, order);
  ret = SBI_PENGLAI_3(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_UNMAP);
  return ret;
}

int handle_ocall_sys_write(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret;
  if(isShadow)
  {
    ((char*)(enclave_instance->kbuffer))[511] = '\0';
    printk((void*)(enclave_instance->kbuffer));
  }
  else
  {
    ((char*)(enclave->kbuffer))[511] = '\0';
    printk((void*)(enclave->kbuffer));
  }
  ret = SBI_PENGLAI_3(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_SYS_WRITE);
  return ret;
}

int handle_ocall_sbrk(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret;
  long size;
  uintptr_t vaddr = 0, order = 0;
  struct pm_area_struct *pma;
  if(isShadow)
  {
    size = (long)(enclave_instance->ocall_arg1);
    pma = (struct pm_area_struct*)(enclave_instance->ocall_arg0);
  }
  else
  {
    pma = (struct pm_area_struct*)(enclave->ocall_arg0);
    size = (long)(enclave->ocall_arg1);
  }
  
  if(size < 0)
  {
    while(pma)
    {
      pma = (struct pm_area_struct*)__va(pma);
      vaddr = (uintptr_t)__va(pma->paddr);

      order = ilog2((pma->size >> RISCV_PGSHIFT) - 1) + 1;
      pma = pma->pm_next;
      //should be freed after set pma to its next
      free_pages(vaddr, order);
    }
  }
  else
  {
    order = ilog2((size >> RISCV_PGSHIFT) - 1) + 1;
    vaddr = penglai_get_free_pages(GFP_KERNEL, order);
    if(!vaddr)
    {
      penglai_eprintf("penglai_enclave_ocall: OCALL_SBRK is failed\r\n"); 
      ret = -1;
      return ret;
    }
  }
  ret = SBI_PENGLAI_5(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_SBRK, __pa(vaddr), (1<<order)*RISCV_PGSIZE);
  return ret;
}

int handle_ocall_read_sect(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int read, ret;
  if (isShadow)
    read = penglai_outer_read(enclave_instance->ocall_arg0);
  else
    read = penglai_outer_read(enclave->ocall_arg0);
  
  ret = SBI_PENGLAI_4(SBI_SM_RESUME_ENCLAVE, resume_id,RESUME_FROM_OCALL, OCALL_READ_SECT, read);
  return ret;
}

int handle_ocall_write_sect(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int write, ret;
  if (isShadow)
  write = penglai_outer_write(enclave_instance->ocall_arg0);
  else
    write = penglai_outer_write(enclave->ocall_arg0);
  
  ret = SBI_PENGLAI_4(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_WRITE_SECT,write);
  return ret;
}

int handle_ocall_create_enclave(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret = 0;
  void *kbuf;
  unsigned long resume_arg_addr;
  // TODO: check ocall_arg0 is NULL or not.
  if (isShadow) 
  {
    // TODO.
    kbuf = (void *) __va(enclave_instance->ocall_arg0);
    resume_arg_addr = enclave_instance->ocall_arg1;
  } 
  else 
  {
    kbuf = (void *) __va(enclave->ocall_arg0);
    resume_arg_addr = enclave->ocall_arg1;
  }
  ocall_create_param_t *ocall_create_param_local = (ocall_create_param_t *) (kbuf);
  
  // step 1. prepare
  //         - copy parameters
  //         - do sanity checks
  /* pass slab-level launched enclave eid */
  struct penglai_enclave_user_param enclave_param;
  enclave_param.eid = ocall_create_param_local->eid;
  /* the elf_ptr and elf_size won't be used in PE create */
  enclave_param.elf_ptr = ocall_create_param_local->elf_file_ptr;
  enclave_param.elf_size = ocall_create_param_local->elf_file_size;
  enclave_param.stack_size = ocall_create_param_local->stack_size;
  if (ocall_create_param_local->encl_type == SHADOW_ENCLAVE)
    enclave_param.stack_size = 0;
  enclave_param.shmid = ocall_create_param_local->shmid;
  enclave_param.shm_offset = ocall_create_param_local->shm_offset;
  enclave_param.shm_size = ocall_create_param_local->shm_size;
  memcpy(enclave_param.name, ocall_create_param_local->encl_name, NAME_LEN);
  memcpy(enclave_param.elf_file_name, ocall_create_param_local->elf_file_name, ELF_FILE_LEN);
  enclave_param.type = ocall_create_param_local->encl_type;
  enclave_param.migrate_arg = ocall_create_param_local->migrate_arg;
  enclave_param.migrate_stack_pages = 0;

  // step 2. create.
  unsigned long vaddr;
  if (enclave_param.migrate_arg)
  {
    snapshot_state_t *state = (snapshot_state_t *)(kbuf + sizeof(ocall_create_param_t));
    enclave_param.migrate_stack_pages = state->stack_sz;
    snapshot_mmap_state_t *mmap = &(state->mmap); 
    snapshot_heap_state_t *heap = &(state->heap);
    unsigned i = 0;
    for (i = 0 ; i < state->stack_sz ; i++)
    {
      vaddr = penglai_get_free_pages(GFP_KERNEL, 1);
      if (!vaddr)
      {
        ret = -1;
        penglai_eprintf("handle_ocall_create_enclave[migration-stack]: penglai_get_free_pages is failed\r\n");
        return ret;
      }
      state->stack_pa[i] = __pa(vaddr);
    }
    for (i = 0 ; i < mmap->mmap_sz ; i++)
    {
      /* The first for vma & pma; The second for content copy */
      vaddr = penglai_get_free_pages(GFP_KERNEL, 1);
      if (!vaddr)
      {
        ret = -1;
        penglai_eprintf("handle_ocall_create_enclave[migration-mmap]: penglai_get_free_pages is failed\r\n");
        return ret;
      }
      mmap->mmap_areas[i].paddr = __pa(vaddr);
    }
    for (i = 0 ; i < heap->heap_sz ; i++)
    {
      vaddr = penglai_get_free_pages(GFP_KERNEL, 1);
      if (!vaddr)
      {
        ret = -1;
        penglai_eprintf("handle_ocall_create_enclave[migration-heap]: penglai_get_free_pages is failed\r\n");
        return ret;
      }
      heap->heap_areas[i].paddr = __pa(vaddr);
    }
  }

  /* alloc page for each entry */
  ret = penglai_enclave_ocall_create((unsigned long)(&enclave_param));
  if (ret < 0) 
  {
    penglai_eprintf("handle_ocall_create_enclave: penglai_enclave_ocall_create is failed\n"); 
  }
  // step 3. resume.
  /* write parameter back to vaddr struct in userspace */
  ret = SBI_PENGLAI_5(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_CREATE_ENCLAVE, resume_arg_addr, enclave_param.eid);
  return ret;
}


int handle_ocall_attest_enclave(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret = 0;
  void *kbuf;
  enclave_t *attest_enclave = NULL;
  // TODO: check ocall_arg0 is NULL or not.
  if (isShadow) 
  {
    // TODO.
    kbuf = (void *) __va(enclave_instance->ocall_arg0);
  } 
  else 
  {
    kbuf = (void *) __va(enclave->ocall_arg0);
  }
  /** 
   * step 1. get the slab-layer eid by idr-layer eid. 
   * Since we cannot acquire idr-layer eid in SM, we jump to driver to handle this.
   */
  ocall_attest_param_t *ocall_attest_param_local = (ocall_attest_param_t *)(kbuf);
  attest_enclave = get_enclave_by_id(ocall_attest_param_local->attest_eid);
  if (!attest_enclave)
  {
    penglai_eprintf("[sdk driver] failed to find this attestee enclave\n");
  }

  /**
   * step 2. return the slab-layer eid back to SM.
  */
  ret = SBI_PENGLAI_4(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_ATTEST_ENCLAVE, attest_enclave->eid);
  /* todo. not finished yet. */
  return ret;
}

int handle_ocall_run_enclave(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret = 0;
  /* the NE's return reason and value */
  unsigned long return_reason = 0, return_value = 0;
  void *kbuf;
  enclave_t *run_enclave = NULL;
 // TODO: check ocall_arg0 is NULL or not.
  if (isShadow) 
  {
    // TODO.
    kbuf = (void *) __va(enclave_instance->ocall_arg0);
  } 
  else 
  {
    kbuf = (void *) __va(enclave->ocall_arg0);
  }
  /**
   * step 1. prepare 
   *          - copy parameters & get eid
   *          - do sanity checks
  */
  ocall_run_param_t *ocall_run_param_local = (ocall_run_param_t *) (kbuf);
  run_enclave = get_enclave_by_id(ocall_run_param_local->run_eid);

  struct penglai_enclave_user_param enclave_param;
  enclave_param.eid = ocall_run_param_local->run_eid;
  enclave_param.isShadow = 0;
  enclave_param.rerun_reason = 0; // todo. support relay page.
  /* update eid in kbuffer from idr-layer to slab-layer */
  ocall_run_param_local->run_eid = run_enclave->eid;
  /**
   * step 2. run NE (in THE LOOP)
   *         return: when IRQ / EXIT / REQUEST
   * \details To handle request, the \param return_reason is diversed. 
   *          (NE_REQUEST_INSPECT, NE_REQUEST_SHARE_PAGE)
   * \details To handle request, the \param return_value saved the VA of request arg in target enclave.
  */
  return_reason = penglai_enclave_ocall_run((unsigned long)(&enclave_param));
  if (return_reason < 0)
  {
    penglai_eprintf("[sdk driver] penglai_enclave_ocall_run failed with return_reason [%d]\n", return_reason);
  }
  return_value = enclave_param.retval;

  /** 
   * step 3. return to PE
   *          return with reason (IRQ / EXIT / ...)
  */
  ret = SBI_PENGLAI_5(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_RUN_ENCLAVE, return_reason, return_value); 
  
  return ret;
}

int handle_ocall_stop_enclave(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret;
  /* todo. not finished yet. */
  return ret;
}

int handle_ocall_resume_enclave(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret = 0;
  /* the NE's return reason and value */
  unsigned long return_reason = 0, return_value = 0;
  // struct pm_area_struct *pma;
  // uintptr_t vaddr = 0, order = 0;
  void *kbuf;
  enclave_t *resume_enclave = NULL;
 // TODO: check ocall_arg0 is NULL or not.
  if (isShadow) 
  {
    // TODO.
    kbuf = (void *) __va(enclave_instance->ocall_arg0);
  } 
  else 
  {
    kbuf = (void *) __va(enclave->ocall_arg0);
  }
  // pma = (struct pm_area_struct*)(enclave->ocall_arg1);

  /**
   * step 1. prepare 
   *          - copy parameters & get eid
   *          - do sanity checks
  */
  ocall_run_param_t *ocall_resume_param_local = (ocall_run_param_t *) (kbuf);
  resume_enclave = get_enclave_by_id(ocall_resume_param_local->run_eid);

  struct penglai_enclave_user_param enclave_param;
  enclave_param.eid = ocall_resume_param_local->run_eid;
  enclave_param.isShadow = 0;
  enclave_param.rerun_reason = ocall_resume_param_local->resume_reason;
  /* update eid in kbuffer from idr-layer to slab-layer */
  ocall_resume_param_local->run_eid = resume_enclave->eid;
  /**
   * step 2. resume NE (in THE LOOP)
   *         return: when IRQ / EXIT / REQUEST
   * \note Different from host-level resume, which converts enclave state from [STOPPED] to [RUNNABLE],
   *       we give a more customized design.
   *       For PE, it can manually control enclave's IRQ by [RETURN_USER_NE_IRQ], whichs convert enclave state
   *       from [RUNNABLE] to [RUNNING] (re-enter its NE children).
   *       For other possible resume_reason values, we will add them in future work.
   * \details After handle request, the return_reason is not diversed. All are RETURN_USER_NE_REQUEST;
   *  by Anonymous Author @ May 15, 2023.
  */
  switch (ocall_resume_param_local->resume_reason)
  {
    case RETURN_USER_NE_REQUEST:
      ret = SBI_PENGLAI_3(SBI_SM_RESPONSE_ENCLAVE, resume_enclave->eid, resume_id, ocall_resume_param_local->response_arg);
      /** 
       * TODO: if the enclave is FRESH (rewinding), clean all pages. 
       * FIX: previous free_enclave_memory have no effect here.
      */
      
      // if (ret > 0)
      // {
      //   while (pma)
      //   {
      //     pma = (struct pm_area_struct *) __va(pma);
      //     vaddr = (uintptr_t)__va(pma->paddr);
      //     order = ilog2((pma->size >> RISCV_PGSHIFT) - 1) + 1;
      //     pma = pma->pm_next;
      //     //should be freed after set pma to its next
      //     free_pages(vaddr, order);
      //   }
      // }
    case RETURN_USER_NE_IRQ:
      return_reason = penglai_enclave_ocall_run((unsigned long)(&enclave_param));
      if (return_reason < 0)
      {
        penglai_eprintf("[sdk driver] penglai_enclave_ocall_run[resume] failed with return_reason [%d]\n", return_reason);
      }
      return_value = enclave_param.retval;
      break;
    case RETURN_USER_EXIT_ENCL:
      return_reason = -1;
      penglai_eprintf("[sdk driver] The enclave has exited, cannot resume\n");
      break;
    default:
      return_reason = -1;
      penglai_eprintf("[sdk driver] bad resume reason: [%d]", ocall_resume_param_local->resume_reason);
      break;
  }

  /**
   * step 3. return to PE
   *         return with reason (IRQ / EXIT / ...)
   *         For requests, we write data back to PE.
  */
  ret = SBI_PENGLAI_5(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_RESUME_ENCLAVE, return_reason, return_value); 
  return ret;
}

int handle_ocall_destroy_enclave(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  /* todo. not finished yet. */
  int ret = 0;
  int target_eid = 0;
  void *kbuf;
  enclave_t *destroy_enclave = NULL;
  if (isShadow)
  {
    kbuf = (void *) __va(enclave_instance->ocall_arg0);
  }
  else 
  {
    kbuf = (void *) __va(enclave->ocall_arg0);
  }
  /**
   * step 1. prepare
   *         - copy parameters & get eid
   *         - do sanity checks
  */
  ocall_destroy_param_t *ocall_destroy_param_local = (ocall_destroy_param_t *)(kbuf);
  destroy_enclave = get_enclave_by_id(ocall_destroy_param_local->destroy_eid);
  if (destroy_enclave == NULL)
  {
    penglai_eprintf("[sdk driver] invalid enclave target: [%d] (slab)\n", ocall_destroy_param_local->destroy_eid);
  }

  struct penglai_enclave_user_param enclave_param;
  enclave_param.eid = ocall_destroy_param_local->destroy_eid;
  enclave_param.isShadow = 0;
  /**
   * step 2. destroy NE 
  */
  // unsigned long op = ocall_destroy_param_local->op;
  // unsigned long dump_arg = ocall_destroy_param_local->dump_arg;
  // target_eid = destroy_enclave->eid;
    
  // /* dump all vmas from SM, might need a more dynamic way. */
  // /* the dumped vma layout will be stored in PE's kbuffer */
  // ret = SBI_PENGLAI_2(SBI_SM_MEMORY_DUMP, target_eid, resume_id);
  // if (ret < 0)
  // {
  //   penglai_eprintf("[sdk driver] SBI_SM_MEMORY_DUMPs failed with retval [%d]\n", ret);
  // }

  ret = penglai_enclave_ocall_destroy((unsigned long)(&enclave_param));
  if (ret < 0)
  {
    penglai_eprintf("[sdk driver] penglai_enclave_ocall_destroy failed with retval [%d]\n", ret);
  }
  /**
   * step 3. return to PE
  */
  ret = SBI_PENGLAI_3(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_DESTROY_ENCLAVE);
  return ret;
}

int handle_ocall_inspect_enclave(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret = 0;
  int target_eid = 0;
  void *kbuf;
  enclave_t *inspect_enclave = NULL;
  if (isShadow) 
  {
    // TODO.
    kbuf = (void *) __va(enclave_instance->ocall_arg0);
  } 
  else 
  {
    kbuf = (void *) __va(enclave->ocall_arg0);
  }
  /**
   * step 1. prepare 
   *          - copy parameters & get eid
   *          - do sanity checks
  */
  ocall_inspect_param_t *ocall_inspect_param_kbuf = (ocall_inspect_param_t *) (kbuf);
  ocall_inspect_param_t ocall_inspect_param_local;
  memcpy((void *)(&ocall_inspect_param_local), ocall_inspect_param_kbuf, sizeof(ocall_inspect_param_t));
  inspect_enclave = get_enclave_by_id(ocall_inspect_param_local.inspect_eid);
  if (!inspect_enclave)
  {
    penglai_eprintf("[sdk driver] target enclave [%d] cannot be accessed.\n", ocall_inspect_param_local.inspect_eid);
  }
  target_eid = inspect_enclave->eid;
  /**
   * step 2. inspect NE
   * inspect result will be written into kbuffer
  */
  if (ocall_inspect_param_local.dump_context == INSPECT_REGS)
  {
    ocall_inspect_param_local.inspect_size = PENGLAI_REGS_STATE_SIZE_MAGIC;
  }
  else if (ocall_inspect_param_local.dump_context == INSPECT_VMA)
  {
    ocall_inspect_param_local.inspect_size = sizeof(enclave_mem_dump_t);
  }
  ret = SBI_PENGLAI_5(SBI_SM_INSPECT_ENCLAVE, target_eid, resume_id, 
                      ocall_inspect_param_local.dump_context,
                      ocall_inspect_param_local.inspect_address, 
                      ocall_inspect_param_local.inspect_size);
  if (ret < 0)
  {
    penglai_eprintf("[sdk driver] SBI_SM_INSPECT_ENCLAVE failed with retval [%d]\n", ret);
  }
  /**
   * step 3. return to PE
  */
  ret = SBI_PENGLAI_5(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_INSPECT_ENCLAVE, 
                      ocall_inspect_param_local.inspect_result, ocall_inspect_param_local.inspect_size);
  return ret;
}

int penglai_enclave_ocall(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  unsigned int ocall_func_id = 0;
  int ret;
  if (!enclave && !enclave_instance)
  {
    penglai_eprintf("penglai_enclave_ocall: enclave or enclave_instance is not exitsed\n");
    return -1;
  }

  if (enclave)
    ocall_func_id = enclave->ocall_func_id;
  if(isShadow && enclave_instance)
    ocall_func_id = enclave_instance->ocall_func_id;
  switch(ocall_func_id)
  {
    case OCALL_MMAP:
    {
      ret = handle_ocall_mmap(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    case OCALL_UNMAP:
    {
      ret = handle_ocall_munmap(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    case OCALL_SYS_WRITE:
    {
      ret = handle_ocall_sys_write(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    case OCALL_SBRK:
    {
      ret = handle_ocall_sbrk(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    /* todo: add our host-level handler here. */
    case OCALL_CREATE_ENCLAVE:
    {
      ret = handle_ocall_create_enclave(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    case OCALL_ATTEST_ENCLAVE:
    {
      ret = handle_ocall_attest_enclave(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    case OCALL_RUN_ENCLAVE:
    {
      ret = handle_ocall_run_enclave(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    case OCALL_STOP_ENCLAVE:
    {
      ret = handle_ocall_stop_enclave(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    case OCALL_RESUME_ENCLAVE:
    {
      ret = handle_ocall_resume_enclave(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    case OCALL_DESTROY_ENCLAVE:
    {
      ret = handle_ocall_destroy_enclave(enclave_instance, enclave, resume_id, isShadow);
      break;
    }    
    case OCALL_INSPECT_ENCLAVE:
    {
      ret = handle_ocall_inspect_enclave(enclave_instance, enclave, resume_id, isShadow);
      break;
    }
    case OCALL_PAUSE_ENCLAVE:
    {
      ret = 0;
      printk("[sdk driver] hey, catch you here!\n");
      break;
    }
    // Some unexpected errors will incur when adding more case clauses 
    default:
    {
      if(ocall_func_id == OCALL_READ_SECT)
      {
        ret = handle_ocall_read_sect(enclave_instance, enclave, resume_id, isShadow);
      }
      else if(ocall_func_id == OCALL_WRITE_SECT)
      {
        ret = handle_ocall_write_sect(enclave_instance, enclave, resume_id, isShadow);
      }
      else if (ocall_func_id == OCALL_RETURN_RELAY_PAGE)
      {
        ret = ENCLAVE_RETURN_USER_MODE;
        break;
      }
      else{
        ret = SBI_PENGLAI_2(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL);
      }
    }
  }
  return ret;
}