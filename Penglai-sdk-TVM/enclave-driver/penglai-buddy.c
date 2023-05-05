#include <linux/mm.h>
#include <linux/slab.h>
#include "riscv64.h"
#include "penglai-buddy.h"
#include "penglai-enclave-driver.h"
#include "buddy.h"
struct global_mem global_mem; 
struct buddy_mm_t* penglai_buddy_init(unsigned long vaddr, unsigned long size)
{
  struct buddy_mm_t* mm = (struct buddy_mm_t*)kmalloc(sizeof(struct buddy_mm_t), GFP_KERNEL);
  vaddr_t free_mem_start = 0;
	vaddr_t free_mem_end = 0;
	struct relay_page *page_meta_start = NULL;
  u64 npages = 0;
  if(!mm)
    return NULL;
  mm->vaddr = vaddr;
  mm->size = size;
  mm->available = 1;
  free_mem_start = vaddr;
	free_mem_end   = vaddr + size;
	npages = (free_mem_end - free_mem_start) / (PAGE_SIZE + sizeof(struct relay_page));
  //start_vaddr is used as relay page
  //the first region is uesd to store the page metadate
  page_meta_start = (struct relay_page *)kmalloc(sizeof(struct relay_page) * npages, GFP_KERNEL);
	/* buddy alloctor for managing physical memory */
	init_buddy(&global_mem, page_meta_start, free_mem_start, npages);
  return mm;
}

unsigned long penglai_buddy_alloc(struct buddy_mm_t* mm, unsigned long size)
{
  struct relay_page *relay_page = NULL;
  int order = ilog2(size/PAGE_SIZE - 1) + 1;
  relay_page = buddy_get_pages(&global_mem, order);
  if (relay_page == NULL)
  {
    penglai_eprintf("there is no enough relay page\n");
    return 0;
  }
  else
  {
    unsigned long addr;
    addr = global_mem.start_addr + PAGE_SIZE * (relay_page - global_mem.first_page);
    return addr;
  }
  return 0;
}

int penglai_buddy_free(struct buddy_mm_t* mm, unsigned long vaddr, unsigned long size)
{
  struct relay_page *relay_page = NULL;
  relay_page = global_mem.first_page + (vaddr - global_mem.start_addr) / PAGE_SIZE;
  buddy_free_pages(&global_mem, relay_page);
  return 0;
}

int penglai_buddy_destroy(struct buddy_mm_t *mm)
{
  unsigned long order;
  if(mm->available)
  {
    mm->available = 0;
    order = ilog2((mm->size >> RISCV_PGSHIFT) - 1) + 1;
    free_pages(mm->vaddr, order);
    kfree(mm);
    return 0;
  }

  return -1;
}
