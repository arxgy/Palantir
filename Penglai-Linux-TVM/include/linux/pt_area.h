#ifndef _LINUX_PT_AREA_H
#define _LINUX_PT_AREA_H
#define DEFAULT_PGD_PAGE_ORDER 5
#define DEFAULT_PMD_PAGE_ORDER 7

void init_pt_area(void);

unsigned long pt_pages_num(void);

unsigned long pt_free_pages_num(void);

char* alloc_pt_pgd_page(void);

char* alloc_pt_pmd_page(void);

char* alloc_pt_pte_page(void);

int free_pt_pgd_page(unsigned long page);

int free_pt_pmd_page(unsigned long page);

int free_pt_pte_page(unsigned long page);

int check_pt_pte_page(unsigned long page);
#endif /* _LINUX_PT_AREA_H */
