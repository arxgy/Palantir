#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/gfp.h>
#include <linux/pt_area.h>
#include <linux/mm.h>

int PGD_PAGE_ORDER=DEFAULT_PGD_PAGE_ORDER;
int PMD_PAGE_ORDER=DEFAULT_PMD_PAGE_ORDER;
int PTE_PAGE_NUM;

char *pt_area_vaddr;
unsigned long pt_area_pages;
unsigned long pt_free_pages;
EXPORT_SYMBOL(pt_area_vaddr);
EXPORT_SYMBOL(pt_area_pages);
EXPORT_SYMBOL(pt_free_pages);
EXPORT_SYMBOL(PGD_PAGE_ORDER);
EXPORT_SYMBOL(PMD_PAGE_ORDER);
EXPORT_SYMBOL(alloc_pt_pte_page);

// extern unsigned long _totalram_pages;

struct pt_page_list{
  struct pt_page_list *next_page;
};

struct pt_page_list *pt_pgd_page_list = NULL;
struct pt_page_list *pt_pgd_free_list = NULL;
struct pt_page_list *pt_pmd_page_list = NULL;
struct pt_page_list *pt_pmd_free_list = NULL;
struct pt_page_list *pt_pte_page_list = NULL;
struct pt_page_list *pt_pte_free_list = NULL;
EXPORT_SYMBOL(pt_pte_page_list);
EXPORT_SYMBOL(pt_pte_free_list);

spinlock_t pt_lock;
EXPORT_SYMBOL(pt_lock);

/* This function allocates a contionuous piece of memory for pt area.
 * PT area is used for storing page tables.
 * This function can only be called after mm_init() is called
 */
void init_pt_area()
{
  //page: computing the number of the page table page
  unsigned long local_totalram_pages = totalram_pages();
  unsigned long pages = (local_totalram_pages % PTRS_PER_PTE) ? (local_totalram_pages/PTRS_PER_PTE + 1) : (local_totalram_pages/PTRS_PER_PTE);
  unsigned long order = ilog2(pages - 1) + 1;

  unsigned long i = 0;
  pt_area_pages = 1 << order;
  PTE_PAGE_NUM = pt_area_pages - (1<<PGD_PAGE_ORDER) - (1<<PMD_PAGE_ORDER);
  pt_free_pages=pt_area_pages;
  pt_area_vaddr = (void*)__get_free_pages(GFP_KERNEL, order);
  memset(pt_area_vaddr, 0, (1<<order)*PAGE_SIZE); 
  if(pt_area_vaddr == NULL)
  {
    panic("ERROR: init_pt_area: alloc pages for pt area failed!\n");
    while(1){}
  }

  //pages: computing the size of te page metadata space
  pages = pt_area_pages * sizeof(struct pt_page_list);
  pages = (pages % PAGE_SIZE) == 0 ? (pages / PAGE_SIZE) : (pages / PAGE_SIZE + 1);
  order = ilog2(pages - 1) + 1;

  pt_pgd_page_list = (struct pt_page_list* )__get_free_pages(GFP_KERNEL, order);
  pt_pmd_page_list = (struct pt_page_list* )__get_free_pages(GFP_KERNEL, order);
  pt_pte_page_list = (struct pt_page_list* )__get_free_pages(GFP_KERNEL, order);
  memset(pt_pgd_page_list, 0, (1<<order)*PAGE_SIZE);
  memset(pt_pmd_page_list, 0, (1<<order)*PAGE_SIZE);
  memset(pt_pte_page_list, 0, (1<<order)*PAGE_SIZE);
  if((pt_pgd_page_list == NULL) || (pt_pmd_page_list == NULL) || (pt_pte_page_list == NULL))
  {
    panic("ERROR: init_pt_area: alloc pages for pt_pgd_pmd_pte_page_list failed!\n");
    while(1){}
  }
  spin_lock_init(&pt_lock);
  spin_lock(&pt_lock);
  for (i = 0; i < (1<<PGD_PAGE_ORDER);++i)
  {
    pt_pgd_page_list[i].next_page = pt_pgd_free_list;
    pt_pgd_free_list = &pt_pgd_page_list[i];
  }
  i = 0;
  for (i = 0; i < (1<<PMD_PAGE_ORDER);++i)
  {
    pt_pmd_page_list[i].next_page = pt_pmd_free_list;
    pt_pmd_free_list = &pt_pmd_page_list[i];
  }
  i = 0;
  for (i = 0; i < PTE_PAGE_NUM;++i)
  {
    pt_pte_page_list[i].next_page = pt_pte_free_list;
    pt_pte_free_list = &pt_pte_page_list[i];
  }
  printk("Init_pt_area: 0x%lx/0x%lx pt pages available!\n",pt_free_pages,pt_area_pages);
  spin_unlock(&pt_lock);
}

unsigned long pt_pages_num()
{
  return pt_area_pages;
}

unsigned long pt_free_pages_num()
{
  return pt_free_pages;
}

char* alloc_pt_pgd_page()
{
  unsigned long pt_page_num;
  char* free_page;
  spin_lock(&pt_lock);

  while (pt_pgd_free_list== NULL){
    printk("alloc_pt_pgd_page: no more page for PGDs\n");
    pagefault_out_of_memory();
    spin_unlock(&pt_lock);
    return NULL;
  }

  pt_page_num = (pt_pgd_free_list - pt_pgd_page_list);
  //need free_page offset
  free_page = pt_area_vaddr + pt_page_num * PAGE_SIZE;
  pt_pgd_free_list = pt_pgd_free_list->next_page;
  pt_free_pages -= 1;

  spin_unlock(&pt_lock);
  if(enclave_module_installed)
  {
    SBI_PENGLAI_ECALL_4(SBI_SM_SET_PTE, SBI_PTE_MEMSET, __pa(free_page), 0, PAGE_SIZE);
  }
  else
  {
    memset(free_page, 0, PAGE_SIZE);
  }
  return free_page;
}

char* alloc_pt_pmd_page()
{
  unsigned long pt_page_num;
  char* free_page;
  spin_lock(&pt_lock);
  while (pt_pmd_free_list == NULL){

    printk("alloc_pt_pmd_page: no more page for PMDs\n");
    pagefault_out_of_memory();
    spin_unlock(&pt_lock);
    return NULL;
  }
  pt_page_num = (pt_pmd_free_list - pt_pmd_page_list);
  //need free_page offset
  free_page = pt_area_vaddr + (pt_page_num + (1<<PGD_PAGE_ORDER))* PAGE_SIZE;
  pt_pmd_free_list = pt_pmd_free_list->next_page;
  pt_free_pages -= 1;
  spin_unlock(&pt_lock);
  if(enclave_module_installed)
  {
    SBI_PENGLAI_ECALL_4(SBI_SM_SET_PTE, SBI_PTE_MEMSET, __pa(free_page), 0, PAGE_SIZE);
  }
  else
  {
    memset(free_page, 0, PAGE_SIZE);
  }
  return free_page;
}

char* alloc_pt_pte_page()
{
  unsigned long pt_page_num;
  char* free_page;
  spin_lock(&pt_lock);

  while (pt_pte_free_list == NULL){
    printk("alloc_pt_pte_page: no more page for PTEs\n");
    pagefault_out_of_memory();
    spin_unlock(&pt_lock);
    return NULL;
  }
  pt_page_num = (pt_pte_free_list - pt_pte_page_list);
  //need free_page offset
  free_page = pt_area_vaddr + (pt_page_num + (1<<PGD_PAGE_ORDER) + (1<<PMD_PAGE_ORDER))* PAGE_SIZE;
  pt_pte_free_list = pt_pte_free_list->next_page;
  pt_free_pages -= 1;
  spin_unlock(&pt_lock);
  if(enclave_module_installed)
  {
    SBI_PENGLAI_ECALL_4(SBI_SM_SET_PTE, SBI_PTE_MEMSET, __pa(free_page), 0, PAGE_SIZE);
  }
  else
  {
    memset(free_page, 0, PAGE_SIZE);
  }
  return free_page;
}

int free_pt_pgd_page(unsigned long page)
{
  unsigned long pt_page_num;

  if(((unsigned long)page % PAGE_SIZE)!=0){
    panic("ERROR: free_pt_pgd_page: page is not PAGE_SIZE aligned!\n");
    return -1; 
  }
  pt_page_num = ((char*)page - pt_area_vaddr) / PAGE_SIZE;
  if(pt_page_num >= (1<<PGD_PAGE_ORDER))
  {
    panic("ERROR: free_pt_pgd_page: page is not in pt_area!\n");
    return -1;
  }

  spin_lock(&pt_lock);

  pt_pgd_page_list[pt_page_num].next_page = pt_pgd_free_list;
  pt_pgd_free_list = &pt_pgd_page_list[pt_page_num];
  pt_free_pages += 1;

  spin_unlock(&pt_lock);

  return  0;
}

int free_pt_pmd_page(unsigned long page)
{
  unsigned long pt_page_num;

  if(((unsigned long)page % PAGE_SIZE)!=0){
    panic("ERROR: free_pt_pmd_page: page is not PAGE_SIZE aligned!\n");
    return -1; 
  }
  pt_page_num = (((char*)page - pt_area_vaddr) / PAGE_SIZE) - (1<<PGD_PAGE_ORDER);
  if(pt_page_num >= (1<<PMD_PAGE_ORDER))
  {
    panic("ERROR: free_pt_pmd_page: page is not in pt_area!\n");
    return -1;
  }

  spin_lock(&pt_lock);

  pt_pmd_page_list[pt_page_num].next_page = pt_pmd_free_list;
  pt_pmd_free_list = &pt_pmd_page_list[pt_page_num];
  pt_free_pages += 1;

  spin_unlock(&pt_lock);

  return  0;
}

int free_pt_pte_page(unsigned long page)
{
  unsigned long pt_page_num;

  if(((unsigned long)page % PAGE_SIZE)!=0){
    panic("ERROR: free_pt_pte_page: page is not PAGE_SIZE aligned!\n");
    return -1; 
  }
  pt_page_num = (((char*)page - pt_area_vaddr) / PAGE_SIZE) - (1<<PGD_PAGE_ORDER) - (1<<PMD_PAGE_ORDER);
  if(pt_page_num >= (pt_area_pages - (1<<PGD_PAGE_ORDER) - (1<<PMD_PAGE_ORDER)))
  {
    panic("ERROR: free_pt_pte_page: page is not in pt_area! %lx\n", page);
    return -1;
  }

  spin_lock(&pt_lock);

  pt_pte_page_list[pt_page_num].next_page = pt_pte_free_list;
  pt_pte_free_list = &pt_pte_page_list[pt_page_num];
  pt_free_pages += 1;

  spin_unlock(&pt_lock);

  return  0;
}

int check_pt_pte_page(unsigned long page)
{
  unsigned long pt_page_num;
  pt_page_num = (((char*)page - pt_area_vaddr) / PAGE_SIZE) - (1<<PGD_PAGE_ORDER) - (1<<PMD_PAGE_ORDER);
  if(pt_page_num >= (pt_area_pages - (1<<PGD_PAGE_ORDER) - (1<<PMD_PAGE_ORDER)))
  {
    return -1;
  }
  return  0;
}
