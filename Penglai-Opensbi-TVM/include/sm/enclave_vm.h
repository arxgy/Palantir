#ifndef _ENCLAVE_VM_H
#define _ENCLAVE_VM_H

#include "enclave.h"
// #include "encoding.h"
#include "vm.h"

/* default layout of enclave */
//#####################
//#   reserved for    #
//#       s mode      #
//##################### 0xffffffe000000000 //actually this is the start address of kernel's image
//#       hole        #
//##################### 0x0000004000000000
//#    shared mem     #
//#     with host     #
//##################### 0x0000003900000000
//#                   #
//#    host mm arg    #
//#                   #
//##################### 0x0000003800000000
//#                   #
//#       stack       #
//#                   #
//##################### 0x0000003000000000
//#       mmap        #
//#                   #
//##################### brk
//#                   #
//#       heap        #
//#                   #
//##################### 0x0000001000000000
//#                   #
//#   text/code/bss   #
//#                   #
//##################### 0x0000000000001000 //not fixed, depends on enclave's lds
//#       hole        #
//##################### 0x0

#define ENCLAVE_DEFAULT_KBUFFER_SIZE    0x1000UL
#define ENCLAVE_DEFAULT_KBUFFER         0xffffffe000000000UL
#define ENCLAVE_DEFAULT_SHM_BASE        0x0000003900000000UL
#define ENCLAVE_DEFAULT_SEC_SHM_BASE    0x0000004000000000UL
#define ENCLAVE_DEFAULT_SEC_SHM_SIZE    (64 * 0x1000 * 0x1000)UL //now default shm_size is 1GB
#define ENCLAVE_DEFAULT_MM_ARG_BASE     0x0000003800000000UL
#define ENCLAVE_DEFAULT_STACK_BASE      0x0000003800000000UL
#define ENCLAVE_DEFAULT_STACK_SIZE      64*1024
#define ENCLAVE_DEFAULT_MMAP_BASE       0x0000003000000000UL
#define ENCLAVE_DEFAULT_HEAP_BASE       0x0000001000000000UL
#define ENCLAVE_DEFAULT_TEXT_BASE       0x0000000000001000UL

#define PAGE_UP(paddr) (((paddr) + RISCV_PGSIZE - 1) & (~(RISCV_PGSIZE - 1)))
#define PAGE_DOWN(paddr) ((addr) & (~(RISCV_PGSIZE - 1)))
#define PADDR_TO_PFN(paddr) ((paddr) >> RISCV_PGSHIFT)
#define PAGE_PFN_SHIFT 10
#define PAGE_ATTRIBUTION(pte) (pte & ((1<<PAGE_PFN_SHIFT) - 1))
#define PTE_VALID(pte) (pte & PTE_V)
#define PTE_ILLEGAL(pte) ((pte & PTE_V) && (pte & PTE_W) && !(pte & PTE_R))
#define VALIDATE_PTE(pte) (pte | PTE_V)
#define INVALIDATE_PTE(pte) (pte & (~PTE_V))
#define PTE_TO_PFN(pte) (pte >> PTE_PPN_SHIFT)
#define PFN_TO_PTE(pfn, attribution) ((pfn<<PAGE_PFN_SHIFT) | attribution)
#define PTE_TO_PA(pte) ((pte >> PTE_PPN_SHIFT)<<RISCV_PGSHIFT)
#define PA_TO_PTE(pa, attribution) (((pa>>RISCV_PGSHIFT)<<PAGE_PFN_SHIFT) | attribution)
#define SATP_PPN  0x00000FFFFFFFFFFFUL
#define IS_PGD(pte) (pte & SATP_MODE_CHOICE)
#define IS_LEAF_PTE(pte) ((pte & PTE_V) && (pte & PTE_R || pte & PTE_X))
#define PGD_TO_PFN(pgd) (pgd & SATP_PPN)
#define RISCV_PGLEVELS ((VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS)

void traverse_vmas(uintptr_t root_page_table, struct vm_area_struct *vma);
int insert_vma(struct vm_area_struct **vma_list, struct vm_area_struct *vma, uintptr_t up_bound);
int delete_vma(struct vm_area_struct **vma_list, struct vm_area_struct *vma);
struct vm_area_struct* find_vma(struct vm_area_struct *vma_list, uintptr_t vaddr, uintptr_t size);
int insert_pma(struct pm_area_struct **pma_list, struct pm_area_struct *pma);
int delete_pma(struct pm_area_struct **pma_list, struct pm_area_struct *pma);

int check_enclave_layout(uintptr_t root_page_table, uintptr_t va_start, uintptr_t va_end, uintptr_t pa_start, uintptr_t pa_end);

void* va_to_pa(uintptr_t* root_page_table, void* va);

int mmap(uintptr_t* root_page_table, struct page_t **free_pages, uintptr_t vaddr, uintptr_t paddr, uintptr_t size);
int unmap(uintptr_t* root_page_table, uintptr_t vaddr, uintptr_t size);
// Debug function:
uintptr_t *pte_walk(uintptr_t *root_page_table, uintptr_t va);

int __check_mapping(pte_t* page_table, uintptr_t pt_area_pgd_base, uintptr_t pt_area_pmd_base, uintptr_t pt_area_pte_base, 
uintptr_t pt_area_end, int level);
int __copy_page_table(pte_t* page_table, struct page_t ** free_page, int level, pte_t* copy_page);
int map_empty_page(uintptr_t* root_page_table, struct page_t **free_pages, uintptr_t vaddr, uintptr_t size);

#endif /* _ENCLAVE_VM_H */
