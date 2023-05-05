#include "penglai-enclave-ocall.h"
#include "penglai-enclave-ioctl.h"
#include "penglai-enclave-driver.h"
#include "penglai-shm.h"
#include "penglai-schrodinger.h"
#include "penglai-enclave-persistency.h"
#include "penglai-enclave-ocall.h"

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