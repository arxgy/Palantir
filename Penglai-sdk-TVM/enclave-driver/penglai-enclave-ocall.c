#include "penglai-enclave-ocall.h"
#include "penglai-enclave-ioctl.h"
#include "penglai-enclave-driver.h"
#include "penglai-shm.h"
#include "penglai-schrodinger.h"
#include "penglai-enclave-persistency.h"
#include "penglai-enclave-ocall.h"
#include "penglai-enclave.h"

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
  // printk("enclave_driver: now we resume to enclave\n");
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
  penglai_printf("[sdk driver] privileged caller eid: [%d]\n", enclave_param.eid);
  penglai_printf("[sdk driver] received elf file name: [%.*s]\n", ELF_FILE_LEN, enclave_param.elf_file_name);
  enclave_param.type = ocall_create_param_local->encl_type;

  // step 2. create.
  ret = penglai_enclave_ocall_create((unsigned long)(&enclave_param));
  if (ret < 0) 
  {
    penglai_eprintf("handle_ocall_create_enclave: penglai_enclave_ocall_create is failed\n"); 
  }
  penglai_printf("[sdk driver] slab-level launcher enclave eid: [%u]\n", ocall_create_param_local->eid);
  penglai_printf("[sdk driver] idr-level launchee enclave eid: [%lu]\n", enclave_param.eid);
  penglai_printf("[sdk driver] address of enclave->ocall_arg1: [%p]\n", (void *)&(enclave->ocall_arg1));
  penglai_printf("[sdk driver] content of enclave->ocall_arg1: [%lu]\n", enclave->ocall_arg1);
  penglai_printf("[sdk driver] content of resume_arg_addr: [%lu]\n", resume_arg_addr);
  // ocall_create_param_local->eid = enclave_param.eid;
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
  penglai_printf("[sdk driver] attestee idr eid: [%d]\n", ocall_attest_param_local->attest_eid);
  attest_enclave = get_enclave_by_id(ocall_attest_param_local->attest_eid);
  if (!attest_enclave)
  {
    penglai_eprintf("[sdk driver] failed to find this attestee enclave\n");
  }
  penglai_printf("[sdk driver] attestee eid from get_enclave_by_id: [%u]\n", attest_enclave->eid);

  /**
   * step 2. return the slab-layer eid back to SM.
  */
  ret = SBI_PENGLAI_4(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_ATTEST_ENCLAVE, attest_enclave->eid);
  /* todo. not finished yet. */
  return ret;
}

int handle_ocall_run_enclave(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret = 0, reason = 0;
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
  penglai_printf("[sdk driver] received run_eid (idr) [%d]\n", ocall_run_param_local->run_eid);
  penglai_printf("[sdk driver] target run_eid (slab) [%d]\n", run_enclave->eid);

  struct penglai_enclave_user_param enclave_param;
  enclave_param.eid = ocall_run_param_local->run_eid;
  enclave_param.isShadow = 0;
  enclave_param.rerun_reason = 0; // todo. support relay page.
  /* update eid in kbuffer from idr-layer to slab-layer */
  ocall_run_param_local->run_eid = run_enclave->eid;
  /**
   * step 2. run NE (in THE LOOP)
   *         return: when IRQ / EXIT
   * \details call our customized function
  */
  reason = penglai_enclave_ocall_run((unsigned long)(&enclave_param));
  if (reason < 0)
  {
    penglai_eprintf("[sdk driver] penglai_enclave_ocall_run failed with retval [%d]\n", ret);
  }

  /** step 3. return to PE
   *          return with reason (IRQ / RELAY PAGE?)
  */
  penglai_printf("[sdk driver] reason: [%d]\n", reason);
  ret = SBI_PENGLAI_4(SBI_SM_RESUME_ENCLAVE, resume_id, RESUME_FROM_OCALL, OCALL_RUN_ENCLAVE, reason); 
  
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
  int ret;
  /* todo. not finished yet. */
  return ret;
}

int handle_ocall_destroy_enclave(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow)
{
  int ret;
  /* todo. not finished yet. */
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
        penglai_printf("penglai_enclave_ocall: [%d]\n", ocall_func_id);
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