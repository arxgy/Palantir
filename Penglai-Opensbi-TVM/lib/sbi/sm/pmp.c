#include "sm/pmp.h"
#include "sm/ipi.h"
#include "sbi/riscv_asm.h"
#include "sbi/sbi_pmp.h"
#include "sbi/sbi_console.h"

/**
 * \brief Set pmp and sync all harts.
 * 
 * \param pmp_idx_arg The pmp index.
 * \param pmp_config_arg The pmp config.
 */
void set_pmp_and_sync(int pmp_idx_arg, struct pmp_config_t pmp_config_arg)
{
  struct pmp_data_t pmp_data;
  u32 source_hart = current_hartid();

  //set current hart's pmp
  set_pmp(pmp_idx_arg, pmp_config_arg);
  //sync all other harts
  SBI_PMP_DATA_INIT(&pmp_data, pmp_config_arg, pmp_idx_arg, source_hart);
  sbi_send_pmp(0xFFFFFFFF&(~(1<<source_hart)), 0, &pmp_data);
  return;
}

/**
 * \brief Clear pmp and sync all harts.
 * 
 * \param pmp_idx_arg The pmp index.
 */
void clear_pmp_and_sync(int pmp_idx)
{
  struct pmp_config_t pmp_config = {0,};
  
  pmp_config.mode = PMP_OFF;
  set_pmp_and_sync(pmp_idx, pmp_config);

  return;
}

//TODO Only handle for the __riscv_64
void set_pmp_reg(int pmp_idx, uintptr_t* pmp_address, uintptr_t* pmp_config)
{
  uintptr_t tmp_pmp_address, tmp_pmp_config;
  tmp_pmp_address = *pmp_address;
  tmp_pmp_config = *pmp_config;
  switch(pmp_idx)
  {
    case 0: 
      PMP_SET(0, 0, tmp_pmp_address, tmp_pmp_config);
      break;
    case 1: 
      PMP_SET(1, 0, tmp_pmp_address, tmp_pmp_config);
      break;
    case 2: 
      PMP_SET(2, 0, tmp_pmp_address, tmp_pmp_config);
      break;
    case 3: 
      PMP_SET(3, 0, tmp_pmp_address, tmp_pmp_config);
      break;
    case 4: 
      PMP_SET(4, 0, tmp_pmp_address, tmp_pmp_config);
      break;
    case 5: 
      PMP_SET(5, 0, tmp_pmp_address, tmp_pmp_config);
      break;
    case 6: 
      PMP_SET(6, 0, tmp_pmp_address, tmp_pmp_config);
      break;
    case 7: 
      PMP_SET(7, 0, tmp_pmp_address, tmp_pmp_config);
      break;
    case 8: 
      PMP_SET(8, 2, tmp_pmp_address, tmp_pmp_config);
      break;
    case 9: 
      PMP_SET(9, 2, tmp_pmp_address, tmp_pmp_config);
      break;
    case 10: 
      PMP_SET(10, 2, tmp_pmp_address, tmp_pmp_config);
      break;
    case 11: 
      PMP_SET(11, 2, tmp_pmp_address, tmp_pmp_config);
      break;
    case 12: 
      PMP_SET(12, 2, tmp_pmp_address, tmp_pmp_config);
      break;
    case 13: 
      PMP_SET(13, 2, tmp_pmp_address, tmp_pmp_config);
      break;
    case 14: 
      PMP_SET(14, 2, tmp_pmp_address, tmp_pmp_config);
      break;
    case 15: 
      PMP_SET(15, 2, tmp_pmp_address, tmp_pmp_config);
      break;
    default:
      break;
  }
  *pmp_address = tmp_pmp_address;
  *pmp_config = tmp_pmp_config;
}

/**
 * \brief set current hart's pmp
 *
 * \param pmp_idx the index of target PMP register
 * \param pmp_cfg the configuration of the PMP register
 */

#define PMP_CONFIG_OFFSET(pmp_idx) ((uintptr_t)PMPCFG_BIT_NUM * (pmp_idx % PMP_PER_CFG_REG))
void set_pmp(int pmp_idx, struct pmp_config_t pmp_cfg)
{
  uintptr_t pmp_address = 0;
  uintptr_t pmp_config = ((pmp_cfg.mode & PMP_A) | (pmp_cfg.perm & (PMP_R|PMP_W|PMP_X))) << PMP_CONFIG_OFFSET(pmp_idx);

  switch(pmp_cfg.mode)
  {
    case PMP_A_TOR:
      pmp_address = pmp_cfg.paddr;
      break;
    case PMP_A_NA4:
      pmp_address = pmp_cfg.paddr;
    case PMP_A_NAPOT:
      if(pmp_cfg.paddr == 0 && pmp_cfg.size == -1UL)
        pmp_address = -1UL;
      else
        pmp_address = (pmp_cfg.paddr | ((pmp_cfg.size>>1)-1)) >> 2;
      break;
    case PMP_OFF:
      pmp_address = 0;
      break;
    default:
      pmp_address = 0;
      break;
  }
  set_pmp_reg(pmp_idx, &pmp_address, &pmp_config);

  return;
}

/**
 * \brief clear the configuration of a PMP register
 *
 * \param pmp_idx the index of target PMP register
 */
void clear_pmp(int pmp_idx)
{
  struct pmp_config_t pmp_cfg;

  pmp_cfg.mode = PMP_OFF;
  pmp_cfg.perm = PMP_NO_PERM;
  pmp_cfg.paddr = 0;
  pmp_cfg.size = 0;
  set_pmp(pmp_idx, pmp_cfg);

  return;
}

/**
 * \brief Get the configuration of a pmp register (pmp_idx)
 *
 * \param pmp_idx the index of target PMP register
 */
struct pmp_config_t get_pmp(int pmp_idx)
{
  struct pmp_config_t pmp = {0,};
  uintptr_t pmp_address = 0;
  uintptr_t pmp_config = 0;
  unsigned long order = 0;
  unsigned long size = 0;

  set_pmp_reg(pmp_idx, &pmp_address, &pmp_config);

  pmp_config >>= (uintptr_t)PMPCFG_BIT_NUM * (pmp_idx % PMP_PER_CFG_REG);
  pmp_config &= PMPCFG_BITS;
  switch(pmp_config & PMP_A)
  {
    case PMP_A_TOR:
      break;
    case PMP_A_NA4:
      size = 4;
      break;
    case PMP_A_NAPOT:
      while(pmp_address & 1)
      {
        order += 1;
        pmp_address >>= 1;
      }
      order += 3;
      size = 1 << order;
      pmp_address <<= (order-1);
      break;
    case PMP_OFF:
      pmp_address = 0;
      size = 0;
      break;
  }

  pmp.mode = pmp_config & PMP_A;
  pmp.perm = pmp_config & (PMP_R | PMP_W | PMP_X);
  pmp.paddr = pmp_address;
  pmp.size = size;

  return pmp;
}

/**
 * \brief Check the validness of a range to be PMP config
 *  	  e.g., the size should be powers of 2
 *
 * \param paddr the start address of the PMP region
 * \param size the size of the PMP region
 */
int illegal_pmp_addr(uintptr_t paddr, uintptr_t size)
{
  if(paddr & (size - 1))
    return -1;
  
  if((size == 0) || (size & (size - 1)))
    return -1;

  if(size < RISCV_PGSIZE)
    return -1;

  return 0;
}

//check whether two regions are overlapped
int region_overlap(uintptr_t pa_0, uintptr_t size_0, uintptr_t pa_1, uintptr_t size_1)
{
  return (pa_0 <= pa_1 && (pa_0 + size_0) > pa_1) || (pa_1 <= pa_0 && (pa_1 + size_1) > pa_0);
}

//check whether two regions are included
int region_contain(uintptr_t pa_0, uintptr_t size_0, uintptr_t pa_1, uintptr_t size_1)
{
  return (pa_0 <= pa_1 && (pa_0 + size_0) >= (pa_1 + size_1))
    || (pa_1 <= pa_0 && (pa_1 + size_1) >= (pa_0 + size_0));
}
