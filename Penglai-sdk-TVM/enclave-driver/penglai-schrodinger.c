#include <asm/sbi.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/csr.h>
#include "riscv64.h"
#include "penglai-enclave.h"
#include "penglai-enclave-page.h"
#include "penglai-schrodinger.h"
#include "penglai-buddy.h"
#include "penglai-enclave-driver.h"

DEFINE_IDR(idr_schrodinger);
DEFINE_SPINLOCK(idr_schrodinger_lock);
DEFINE_SPINLOCK(schrodinger_get_lock);

struct buddy_mm_t *mm = NULL;

int unmap_schrodinger_mm_region(unsigned long vaddr, unsigned long size)
{
  uintptr_t va = vaddr;
  uintptr_t va_end = vaddr + size;
  for(; va < va_end; va += RISCV_PGSIZE)
  {
    uintptr_t *ptes = (uintptr_t*)__va(csr_read(sptbr) << RISCV_PGSHIFT);
    int level = RISCV_PT_LEVEL - 1;
    for(; level >= 0; --level)
    {
      uintptr_t pos = (va >> (RISCV_PGSHIFT + RISCV_PT_LEVELBITS* level)) & ((1 << RISCV_PT_LEVELBITS) - 1);
      uintptr_t pte = ptes[pos];
      if(!(pte & PTE_V))
        break;
      if((pte & PTE_R) || (pte & PTE_X))
      {
        //clear the pt entry
        int ret = SBI_PENGLAI_4(SBI_SM_SET_PTE, SBI_SET_PTE_ONE, __pa(&(ptes[pos])), 0, 0);
        if(ret != 0)
        {
          penglai_eprintf("failed to unmap 0x%lx\n", va);
          return -1;
        }
        break;
      }
      ptes = (uintptr_t*)__va((pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT);
    }
  }

  return 0;
}

int remap_schrodinger_mm_region(unsigned long vaddr, unsigned long size)
{
  uintptr_t va = vaddr;
  uintptr_t va_end = vaddr + size;
  int ret;
  for(; va < va_end; va += RISCV_PGSIZE)
  {
    uintptr_t *ptes = (uintptr_t*)__va(csr_read(sptbr) << RISCV_PGSHIFT);
    int level = RISCV_PT_LEVEL - 1;
    for(; level >= 0; --level)
    {
      uintptr_t pos = (va >> (RISCV_PGSHIFT + RISCV_PT_LEVELBITS* level)) & ((1 << RISCV_PT_LEVELBITS) - 1);
      uintptr_t pte = ptes[pos];
      if(!(pte & PTE_V))
      {
        uintptr_t pa = __pa(va);
        //FIXME: the page attribution can be configured by user
        pte = ((pa >> RISCV_PGSHIFT) << PTE_PPN_SHIFT) | PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D;
        ret = SBI_PENGLAI_4(SBI_SM_SET_PTE, SBI_SET_PTE_ONE, __pa(&(ptes[pos])), pte, 0);
        if(ret != 0)
        {
          penglai_eprintf("failed to remap 0x%lx\n", va);
          return -1;
        }
        break;
      }
      ptes = (uintptr_t*)__va((pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT);
    }
  }

  return 0;
}

struct penglai_schrodinger *penglai_schrodinger_find(int id)
{
  struct penglai_schrodinger *p = NULL;

  spin_lock_bh(&idr_schrodinger_lock);
  p = idr_find(&idr_schrodinger, id);
  spin_unlock_bh(&idr_schrodinger_lock);

  return p;
}

int penglai_schrodinger_alloc(struct penglai_schrodinger* p)
{
  int ret = 0;

  spin_lock_bh(&idr_schrodinger_lock);
  ret = idr_alloc(&idr_schrodinger, p, MIN_PENGLAI_SCHRODINGER_ID, MAX_PENGLAI_SCHRODINGER_ID, GFP_KERNEL);
  spin_unlock_bh(&idr_schrodinger_lock);

  if(ret < MIN_PENGLAI_SCHRODINGER_ID || ret >= MAX_PENGLAI_SCHRODINGER_ID)
  {
    penglai_eprintf("failed to map schrodinger id %dx\n", p->id);
    ret = -1;
  }

  return ret;
}

struct penglai_schrodinger* penglai_schrodinger_free(int id)
{
  struct penglai_schrodinger* p = NULL;

  spin_lock_bh(&idr_schrodinger_lock);
  p = idr_find(&idr_schrodinger, id);
  if(!p || p->refcount > 0)
  {
    p = NULL;
    goto out;
  }
  p = idr_remove(&idr_schrodinger, id);

out:
  spin_unlock_bh(&idr_schrodinger_lock);
  return p;
}

int penglai_schrodinger_get(struct file* filep, unsigned long args)
{
  int ret = 0;
  struct penglai_schrodinger_get_param* param = (struct penglai_schrodinger_get_param*)args;
  unsigned long vaddr = 0;
  struct penglai_schrodinger* p = NULL;

  spin_lock(&schrodinger_get_lock);

  if(param->size < RISCV_PGSIZE || param->size & (RISCV_PGSIZE-1))
  {
    spin_unlock(&schrodinger_get_lock);
    return -1;
  }
  // schrodinger_alloc中分配用的buddy entry怎么只有一个？ 
  vaddr = schrodinger_alloc(param->size);
  p = kmalloc(sizeof(struct penglai_schrodinger), GFP_KERNEL);
  if(!p || !vaddr)
  {
    ret = -1;
    goto error;
  }

  p->vaddr = vaddr;
  p->size = param->size;
  p->refcount = 0;
  p->id = penglai_schrodinger_alloc(p);
  if(p->id < 0)
  {
    ret = -1;
    goto error;
  }
  spin_unlock(&schrodinger_get_lock);
  return p->id;

error:
  if(p)
    kfree(p);
  if(vaddr)
    schrodinger_free(vaddr, param->size);
  spin_unlock(&schrodinger_get_lock);
  return ret;
}

int penglai_schrodinger_at(struct file* filep, unsigned long args)
{
  int ret = 0;
  struct penglai_schrodinger_at_param* param = (struct penglai_schrodinger_at_param*)args;
  struct penglai_schrodinger* p = penglai_schrodinger_find(param->id);
  struct dev_private_data_t *private_data = filep->private_data;
  if(!p || p->refcount >= 1)
  {
    penglai_eprintf("pengali_schrodinger_at: failed to bind schrodinger%d\n", param->id);
    return -1;
  }

  private_data->mmap_vaddr = p->vaddr;
  private_data->mmap_size = p->size;
  p->refcount += 1;

  param->size = p->size;
  return ret;
}

int penglai_schrodinger_dt(struct file* filep, unsigned long args)
{
  int ret = 0;
  struct penglai_schrodinger_dt_param* param = (struct penglai_schrodinger_dt_param*)args;
  struct penglai_schrodinger* p = penglai_schrodinger_find(param->id);
  struct dev_private_data_t *private_data = filep->private_data;
  if(!p || p->refcount <= 0)
  {
    penglai_eprintf("penglai_schrodinger_dt: failed to unbind schrodinger%d\n", param->id);
    return -1;
  }

  private_data->mmap_vaddr = 0;
  private_data->mmap_size = 0;
  p->refcount -= 1;

  param->size = p->size;

  return ret;
}

int penglai_schrodinger_ctl(struct file* filep, unsigned long args)
{
  int ret = 0;
  struct penglai_schrodinger_ctl_param* param = (struct penglai_schrodinger_ctl_param*)args;
  struct penglai_schrodinger* p = penglai_schrodinger_free(param->id);
  unsigned long addr, size;
  if(!p)
  {
    penglai_eprintf("penglai_schrodinger_ctl: failed to delete schrodinger%d\n", param->id);
    return -1;
  }

  addr = p->vaddr;
  size = p->size;
  kfree(p);
  schrodinger_free(addr, size);

  return ret;
}

int schrodinger_init(unsigned long vaddr, unsigned long size)
{
  int ret;
  if(mm)
    return -1;
  penglai_printf("KERNEL schrodinger_init: init \n");
  ret = SBI_PENGLAI_2(SBI_SM_SCHRODINGER_INIT, __pa(vaddr), size);
  if(ret != 0)
    return -1;

  unmap_schrodinger_mm_region(vaddr, size);
  //init the allocator for schrodinger page
  mm = penglai_buddy_init(vaddr, size);
  if(!mm)
  {
    remap_schrodinger_mm_region(vaddr, size);
    return -1;
  }

  return 0;
}

unsigned long schrodinger_alloc(unsigned long size)
{
  unsigned long ret;
  if(!mm)
    return 0;

  ret = penglai_buddy_alloc(mm, size);
  if(!ret)
    return 0;

  return ret;
}

int schrodinger_free(unsigned long vaddr, unsigned long size)
{
  int ret;
  if(!mm)
    return -1;

  ret = penglai_buddy_free(mm, vaddr, size);
  if(ret != 0)
    return -1;

  return 0;
}
