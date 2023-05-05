
#include "penglai-enclave.h"
#include "penglai-enclave-driver.h"
DEFINE_IDR(idr_enclave);
DEFINE_SPINLOCK(idr_enclave_lock);

int check_eid(unsigned int eid)
{
  if (eid < ENCLAVE_IDR_MIN || eid >= ENCLAVE_IDR_MAX)
    return -1;
  
  return 0;
}

unsigned int enclave_idr_alloc(enclave_t* enclave)
{
  unsigned int eid;

  spin_lock_bh(&idr_enclave_lock);
  eid = idr_alloc(&idr_enclave, enclave, ENCLAVE_IDR_MIN, ENCLAVE_IDR_MAX, GFP_KERNEL);
  spin_unlock_bh(&idr_enclave_lock);
  
  if (check_eid(eid) < 0)
  {
    penglai_eprintf("enclave_idr_alloc: eid is out of range\n");
    return 0;
  }
  
  return eid;
}

enclave_t* enclave_idr_remove(unsigned int eid) 
{
  enclave_t* enclave;

  spin_lock_bh(&idr_enclave_lock);
  enclave = idr_remove(&idr_enclave, eid);
  spin_unlock_bh(&idr_enclave_lock);

  return enclave;
}

enclave_t* get_enclave_by_id(unsigned int eid)
{
  enclave_t* enclave;

  spin_lock_bh(&idr_enclave_lock);
  enclave = idr_find(&idr_enclave, eid); 
  spin_unlock_bh(&idr_enclave_lock);

  return enclave;
}

unsigned int enclave_instance_idr_alloc(enclave_instance_t* enclave_instance)
{
  unsigned int eid;

  spin_lock_bh(&idr_enclave_lock);
  eid = idr_alloc(&idr_enclave, enclave_instance, ENCLAVE_IDR_MIN, ENCLAVE_IDR_MAX, GFP_KERNEL);
  spin_unlock_bh(&idr_enclave_lock);
  
  if (check_eid(eid) < 0)
  {
    penglai_eprintf("enclave_instance_idr_alloc: eid is out of range\n");
    return 0;
  }
  
  return eid;
}

enclave_instance_t* enclave_instance_idr_remove(unsigned int ueid) 
{
  enclave_instance_t* enclave_instance;

  spin_lock_bh(&idr_enclave_lock);
  enclave_instance = idr_remove(&idr_enclave, ueid);
  spin_unlock_bh(&idr_enclave_lock);

  return enclave_instance;
}

enclave_instance_t* get_enclave_instance_by_id(unsigned int ueid)
{
  enclave_instance_t* enclave_instance;

  spin_lock_bh(&idr_enclave_lock);
  enclave_instance = idr_find(&idr_enclave, ueid); 
  spin_unlock_bh(&idr_enclave_lock);

  return enclave_instance;
}

enclave_t* create_enclave(int total_pages, char* name, enclave_type_t type)
{
  vaddr_t addr = 0;
  vaddr_t kbuffer = 0;
  enclave_t* enclave = kmalloc(sizeof(enclave_t), GFP_KERNEL);
  enclave_mem_t* enclave_mem = kmalloc(sizeof(enclave_mem_t), GFP_KERNEL);
  phys_addr_t device_phys_addr = 0;

  //size @ total enclave memory size in byte;
  int size;
  unsigned long order = ilog2(total_pages-1) + 1;
  unsigned long count = 0x1 << order;
  if(!enclave || !enclave_mem)
  {
    penglai_eprintf("no enough kernel memory\n");
    goto free_enclave;
  }

  if(!addr || !device_phys_addr)
  {
    addr = penglai_get_free_pages(GFP_KERNEL, order);
  }
  if(!addr)
  {
    penglai_eprintf("failed to allocate enclave page in kernel(s) %lx\n", count);
    goto free_enclave;
  }
  memset((void*)addr, 0, RISCV_PGSIZE*count);
  if(type == NORMAL_ENCLAVE)
  {
    kbuffer = penglai_get_free_pages(GFP_KERNEL, ENCLAVE_DEFAULT_KBUFFER_ORDER);
    if(!kbuffer)
    {
      penglai_eprintf("failed to allocate kbuffer\n");
      goto free_enclave;
    }
    memset((void*)kbuffer, 0, ENCLAVE_DEFAULT_KBUFFER_SIZE);
  }
  size = RISCV_PGSIZE*count;
  INIT_LIST_HEAD(&enclave_mem->free_mem);
  enclave_mem_int(enclave_mem, addr, size, __pa(addr));
  enclave->enclave_mem = enclave_mem;
  enclave->satp = csr_read(sptbr);
  enclave->kbuffer = kbuffer;
  enclave->kbuffer_size = ENCLAVE_DEFAULT_KBUFFER_SIZE;
  enclave->type = type;
  memcpy(enclave->name, name, NAME_LEN);
  return enclave;

free_enclave:

  if(enclave) 
    kfree(enclave);
  if(enclave_mem) 
    kfree(enclave_mem);
  if(kbuffer)
    free_pages(kbuffer, ENCLAVE_DEFAULT_KBUFFER_ORDER);
  if(addr)
    free_pages(addr, order);

  return NULL;
}

int destroy_enclave(enclave_t* enclave)
{
  enclave_mem_t* enclave_mem;

  if(!enclave)
  {
    penglai_eprintf("destroy_enclave: enclave is not existed\n");
    return -1;
  }

  enclave_mem = enclave->enclave_mem;
  
  if (!enclave_mem)
  {
    penglai_eprintf("destroy_enclave: enclave mem is not existed\n");
    return -1;
  }
  
  enclave_mem_destroy(enclave_mem);

  if(enclave->kbuffer)
  {
    free_pages(enclave->kbuffer, ENCLAVE_DEFAULT_KBUFFER_ORDER);
  }


  kfree(enclave_mem);
  kfree(enclave);

  return 0;
}
