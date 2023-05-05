#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include "penglai-shm.h"
#include "penglai-enclave-driver.h"
#include "riscv64.h"

DEFINE_SPINLOCK(buddy_lock);
DEFINE_IDR(idr_shm);
DEFINE_SPINLOCK(idr_shm_lock);

struct penglai_shm *penglai_shm_find(int shmid)
{
  struct penglai_shm* shm = NULL;

  spin_lock_bh(&idr_shm_lock);
  shm = idr_find(&idr_shm, shmid);
  spin_unlock_bh(&idr_shm_lock);

  return shm;
}

int penglai_shm_alloc(struct penglai_shm* shm)
{
  int ret = 0;

  spin_lock_bh(&idr_shm_lock);
  ret = idr_alloc(&idr_shm, shm, MIN_PENGLAI_SHMID, MAX_PENGLAI_SHMID, GFP_KERNEL);
  spin_unlock_bh(&idr_shm_lock);

  if(ret < MIN_PENGLAI_SHMID || ret >= MAX_PENGLAI_SHMID)
  {
    penglai_eprintf("failed to map shmid %d to ptr 0x%lx\n", shm->shmid, (unsigned long)shm);
    ret = -1;
  }

  return ret;
}

struct penglai_shm* penglai_shm_free(int shmid)
{
  struct penglai_shm* shm = NULL;

  spin_lock_bh(&idr_shm_lock);
  shm = idr_find(&idr_shm, shmid);
  if(!shm || shm->refcount > 0)
    goto out;
  shm = idr_remove(&idr_shm, shmid);

out:
  spin_unlock_bh(&idr_shm_lock);
  return shm;
}

int penglai_shmget(struct file* filep, unsigned long args)
{
  int ret = 0;
  struct penglai_shmget_param* param = (struct penglai_shmget_param*)args;
  unsigned long vaddr = 0;
  unsigned long order = 0;
  struct penglai_shm* shm = NULL;
  if(param->size < RISCV_PGSIZE || param->size & (RISCV_PGSIZE-1))
  {
    penglai_eprintf("penglai_shmget: shm size must align with RISCV_PGSIZE\n");
    return -1;
  }

  order = ilog2((param->size >> RISCV_PGSHIFT) - 1) + 1;
  vaddr = __get_free_pages(GFP_KERNEL, order);
  shm = kmalloc(sizeof(struct penglai_shm), GFP_KERNEL);
  if(!shm || !vaddr)
  {
    ret = -1;
    penglai_eprintf("can not get the free page or kmalloc is failed \n");
    goto error;
  }

  shm->vaddr = vaddr;
  shm->size = param->size;
  shm->refcount = 0;
  spin_lock(&buddy_lock);
  shm->shmid = penglai_shm_alloc(shm);
  spin_unlock(&buddy_lock);
  if(shm->shmid < 0)
  {
    ret = -1;
    penglai_eprintf("can not alloc the shmid \n");
    goto error;
  }
  return shm->shmid;

error:
  if(shm)
    kfree(shm);
  if(vaddr)
    free_pages(vaddr, order);

  return ret;
}

int penglai_shmat(struct file* filep, unsigned long args)
{
  int ret = 0;
  struct penglai_shmat_param* param = (struct penglai_shmat_param*)args;
  struct penglai_shm* shm = penglai_shm_find(param->shmid);
  struct dev_private_data_t *private_data;
  if(!shm)
  {
    penglai_eprintf("penglai_shmat:penglai_shmat: failed to bind shm%d\n", param->shmid);
    return -1;
  }

  private_data = filep->private_data;
  private_data->mmap_vaddr = shm->vaddr;
  private_data->mmap_size = shm->size;
  shm->refcount += 1;

  param->size = shm->size;
  return ret;
}

int penglai_shmdt(struct file* filep, unsigned long args)
{
  int ret = 0;
  struct penglai_shmdt_param* param = (struct penglai_shmdt_param*)args;
  struct penglai_shm* shm = penglai_shm_find(param->shmid);
  struct dev_private_data_t *private_data;
  if(!shm || shm->refcount <= 0)
  {
    penglai_eprintf("penglai_shmdt: failed to unbind shm%d\n", param->shmid);
    return -1;
  }

  private_data = filep->private_data;
  private_data->mmap_vaddr = 0;
  private_data->mmap_size = 0;
  shm->refcount -= 1;

  param->size = shm->size;

  return ret;
}

int penglai_shmctl(struct file* filep, unsigned long args)
{
  int ret = 0;
  struct penglai_shmctl_param* param = (struct penglai_shmctl_param*)args;
  struct penglai_shm* shm = penglai_shm_free(param->shmid);
  unsigned long addr, size, order;
  if(!shm)
  {
    penglai_eprintf("penglai_shmctl: failed to delete shm%d\n", param->shmid);
    return -1;
  }

  addr = shm->vaddr;
  size = shm->size;
  order = ilog2((size >> RISCV_PGSHIFT) - 1) + 1;
  free_pages(addr, order);
  kfree(shm);

  return ret;
}
