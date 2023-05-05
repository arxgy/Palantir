#ifndef _PMP_H
#define _PMP_H

#include "sbi/sbi_types.h"
#include "sbi/riscv_encoding.h"
#include "sbi/sbi_hartmask.h"

#define NPMP 8

#define PMP_OFF   0x00
#define PMP_NO_PERM  0

#define PMPCFG_BIT_NUM            8
#define PMPCFG_BITS               0xFF
#define PMP_PER_CFG_REG           (sizeof(uintptr_t) * 8 / PMPCFG_BIT_NUM)

#define PMP_SET(num, cfg_index, pmpaddr, pmpcfg) do { \
  uintptr_t oldcfg = csr_read(CSR_PMPCFG##cfg_index); \
  pmpcfg |= (oldcfg & ~((uintptr_t)PMPCFG_BITS << (uintptr_t)PMPCFG_BIT_NUM*(num%PMP_PER_CFG_REG))); \
  asm volatile ("la t0, 1f\n\t" \
                "csrrw t0, mtvec, t0\n\t" \
                "csrw pmpaddr"#num", %0\n\t" \
                "csrw pmpcfg"#cfg_index", %1\n\t" \
                "sfence.vma\n\t"\
                ".align 2\n\t" \
                "1: csrw mtvec, t0 \n\t" \
                : : "r" (pmpaddr), "r" (pmpcfg) : "t0"); \
} while(0)

#define PMP_READ(num, cfg_index, pmpaddr, pmpcfg) do { \
  asm volatile("csrr %0, pmpaddr"#num : "=r"(pmpaddr) :); \
  asm volatile("csrr %0, pmpcfg"#cfg_index : "=r"(pmpcfg) :); \
} while(0)

struct pmp_config_t
{
  uintptr_t paddr;
  unsigned long size;
  uintptr_t perm;
  uintptr_t mode;
};

struct pmp_data_t
{
  struct pmp_config_t pmp_config_arg;
  int pmp_idx_arg;
  struct sbi_hartmask smask;
};

#define SBI_PMP_DATA_INIT(__ptr, __pmp_config_arg, __pmp_idx_arg, __src) \
do { \
	(__ptr)->pmp_config_arg = (__pmp_config_arg); \
	(__ptr)->pmp_idx_arg = (__pmp_idx_arg); \
	SBI_HARTMASK_INIT_EXCEPT(&(__ptr)->smask, (__src)); \
} while (0)

void set_pmp_and_sync(int pmp_idx, struct pmp_config_t);
void clear_pmp_and_sync(int pmp_idx);
void set_pmp(int pmp_idx, struct pmp_config_t);
void clear_pmp(int pmp_idx);
struct pmp_config_t get_pmp(int pmp_idx);
int region_overlap(uintptr_t pa0, uintptr_t size0, uintptr_t pa1, uintptr_t size1);
int region_contain(uintptr_t pa0, uintptr_t size0, uintptr_t pa1, uintptr_t size1);
int illegal_pmp_addr(uintptr_t addr, uintptr_t size);

#endif /* _PMP_H */
