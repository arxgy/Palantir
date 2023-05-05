#ifndef __RISCV64__
#define __RISCV64__

#include <asm/page.h>
#include <linux/types.h>

#define INSERT_FIELD(val, which, fieldval) (((val) & ~(which)) | ((fieldval) * ((which) & ~((which)-1))))

#define PRV_U 0
#define PRV_S 1
#define PRV_H 2
#define PRV_M 3

#define SATP32_MODE 0x80000000
#define SATP32_ASID 0x7FC00000
#define SATP32_PPN  0x003FFFFF
#define SATP64_MODE 0xF000000000000000
#define SATP64_ASID 0x0FFFF00000000000
#define SATP64_PPN  0x00000FFFFFFFFFFF

#define SATP_MODE_OFF  0
#define SATP_MODE_SV32 1
#define SATP_MODE_SV39 8
#define SATP_MODE_SV48 9
#define SATP_MODE_SV57 10
#define SATP_MODE_SV64 11

/* page table entry (PTE) fields */
#define PTE_V     0x001 // Valid
#define PTE_R     0x002 // Read
#define PTE_W     0x004 // Write
#define PTE_X     0x008 // Execute
#define PTE_U     0x010 // User
#define PTE_G     0x020 // Global
#define PTE_A     0x040 // Accessed
#define PTE_D     0x080 // Dirty
#define PTE_SOFT  0x300 // Reserved for Software

#define PTE_PPN_SHIFT 10

#define PTE_TABLE(PTE) (((PTE) & (PTE_V | PTE_R | PTE_W | PTE_X)) == PTE_V)

#define MSTATUS_SD MSTATUS64_SD
#define SSTATUS_SD SSTATUS64_SD
#define RISCV_PGLEVEL_BITS 9

#define RISCV_PGSHIFT 12
#define RISCV_PGSIZE (1 << RISCV_PGSHIFT)

#define MEGAPAGE_SIZE ((uintptr_t)(RISCV_PGSIZE << RISCV_PGLEVEL_BITS))
#define SATP_MODE_CHOICE INSERT_FIELD(0, SATP64_MODE, SATP_MODE_SV39)
#define VA_BITS 39
#define GIGAPAGE_SIZE (MEGAPAGE_SIZE << RISCV_PGLEVEL_BITS)

#define PTE_VALID(pte) (pte & PTE_V)
#define PTE_ILLEGAL(pte) ((pte & PTE_V) && (pte & PTE_W) && !(pte & PTE_R))
#define VALIDATE_PTE(pte) (pte | PTE_V)
#define INVALIDATE_PTE(pte) (pte & (~PTE_V))
#define PTE_TO_PFN(pte) (pte >> PTE_PPN_SHIFT)
#define PFN_TO_PTE(pfn, attribution) ((pfn<<PAGE_PFN_SHIFT) | attribution)
#define PTE_TO_PA(pte) ((pte >> PTE_PPN_SHIFT)<<RISCV_PGSHIFT)
#define PA_TO_PTE(pa, attribution) (((pa>>RISCV_PGSHIFT)<<PAGE_PFN_SHIFT) | attribution)
#define IS_PGD(pte) (pte & SATP_MODE_CHOICE)
#define IS_LEAF_PTE(pte) ((pte & PTE_V) && (pte & PTE_R || pte & PTE_X))
#define PADDR_TO_PFN(paddr) ((paddr) >> RISCV_PGSHIFT)

static inline void flush_tlb(void)
{
  asm volatile ("sfence.vma");
}

#endif
