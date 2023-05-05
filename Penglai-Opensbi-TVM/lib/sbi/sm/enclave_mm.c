#include "sm/sm.h"
#include "sm/enclave.h"
#include "sm/enclave_vm.h"
#include "sm/enclave_mm.h"
#include "sbi/riscv_atomic.h"
#include "sbi/sbi_math.h"

// mm_region_list maintains the (free?) secure pages in monitor
static struct mm_region_list_t *mm_region_list;
static spinlock_t mm_regions_lock = SPINLOCK_INIT;
extern spinlock_t mbitmap_lock;


/**
 * \brief This function will turn a set of untrusted pages to secure pages.
 * Frist, it will valiated the range is valid.
 * Then, it ensures the pages are untrusted/public now.
 * Afterthat, it updates the metadata of the pages into secure (or private).
 * Last, it unmaps the pages from the host PTEs.
 *
 * FIXME: we should re-consider the order of the last two steps.
 * 
 * \param paddr the check physical address. 
 * \param size the check physical size
 */
int check_and_set_secure_memory(unsigned long paddr, unsigned long size)
{
  int ret = 0;
  if(paddr & (RISCV_PGSIZE-1) || size < RISCV_PGSIZE || size & (RISCV_PGSIZE-1))
  {
    ret = -1;
    return ret;
  }

  spin_lock(&mbitmap_lock);

  if(test_public_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT) != 0)
  {
    ret = -1;
    goto out;
  }
  set_private_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT);
  unmap_mm_region(paddr, size);

out:
  spin_unlock(&mbitmap_lock);
  return ret;
}

/**
 * \brief Free a set of secure pages.
 * It turn the secure pgaes into unsecure (or public)
 * and remap all the pages back to host's PTEs.
 * 
 * \param paddr The free physical address.
 * \param size The free memory size. 
 */
int __free_secure_memory(unsigned long paddr, unsigned long size)
{
  int ret = 0;

  set_public_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT);
  remap_mm_region(paddr, size);
  return ret;
}

/**
 * \brief Free a set of secure pages.
 * It turn the secure pgaes into unsecure (or public)
 * and remap all the pages back to host's PTEs.
 * 
 * \param paddr The free physical address.
 * \param size The free memory size. 
 */
int free_secure_memory(unsigned long paddr, unsigned long size)
{
  int ret = 0;
  spin_lock(&mbitmap_lock);

  set_public_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT);
  remap_mm_region(paddr, size);

  spin_unlock(&mbitmap_lock);
  return ret;
}

/**
 * \brief mm_init adds a new range into mm_region_list for monitor/enclaves to use.
 * 
 * \param paddr The init physical address.
 * \param size The init memory size. 
 */
uintptr_t mm_init(uintptr_t paddr, unsigned long size)
{
  uintptr_t ret = 0;
  spin_lock(&mm_regions_lock);

  if(size < RISCV_PGSIZE || (paddr & (RISCV_PGSIZE-1)) || (size & (RISCV_PGSIZE-1)))
  {
    ret = -1;
    goto out;
  }

  if(check_and_set_secure_memory(paddr, size) != 0)
  {
    ret = -1;
    goto out;
  }

  struct mm_region_list_t* list = (struct mm_region_list_t*)paddr;
  list->paddr = paddr;
  list->size = size;
  list->next = mm_region_list;
  mm_region_list = list;

out:
  spin_unlock(&mm_regions_lock);
  return ret;
}

/**
 * \brief mm_alloc returns a memory region
 * The returned memory size is put into resp_size, and the addr in return value.
 * 
 * \param req_size The request memory size.
 * \param resp_size The response memory size. 
 */
void* mm_alloc(unsigned long req_size, unsigned long *resp_size)
{
  void* ret = NULL;
  spin_lock(&mm_regions_lock);

  if(!mm_region_list)
  {
    ret = NULL;
    goto out;
  }

  ret = (void*)(mm_region_list->paddr);
  *resp_size = mm_region_list->size;
  mm_region_list = mm_region_list->next;

out:
  spin_unlock(&mm_regions_lock);
  return ret;
}

/**
 * \brief mm_free frees a memory region back to mm_region_list.
 * 
 * \param paddr The physical address need to be reclaimed.
 * \param size The reclaimed memory size. 
 */
int mm_free(void* paddr, unsigned long size)
{
  int ret = 0;
  spin_lock(&mm_regions_lock);

  if(size < RISCV_PGSIZE || ((uintptr_t)paddr & (RISCV_PGSIZE-1)) != 0)
  {
    ret = -1;
    goto out;
  }

  struct mm_region_list_t* list = (struct mm_region_list_t*)paddr;
  list->paddr = (uintptr_t)paddr;
  list->size = size;
  list->next = mm_region_list;
  mm_region_list = list;

out:
  spin_unlock(&mm_regions_lock);
  return ret;
}

/**
 * \brief grant enclave access to enclave's memory, it's an empty function now.
 * 
 * \param paddr The physical address need to be reclaimed.
 * \param size The reclaimed memory size. 
 */
int grant_enclave_access(struct enclave_t* enclave)
{
  return 0;
}

/**
 * \brief It's an empty function now.
 * 
 * \param enclave The current enclave. 
 */
int retrieve_enclave_access(struct enclave_t *enclave)
{
  return 0;
}
