#include "sbi/riscv_atomic.h"
#include "sbi/sbi_tvm.h"
#include "sbi/sbi_console.h"
#include "sm/sm.h"
#include "sm/pmp.h"
#include "sm/enclave.h"
#include "sm/enclave_vm.h"
#include "sm/enclave_mm.h"
#include "sm/server_enclave.h"
#include "sm/platform/pt_area/platform.h"

//get the ppn from an pte entry
static uintptr_t pte_ppn(pte_t pte)
{
  return pte >> PTE_PPN_SHIFT;
}

/**
 * Init secure monitor by invoking platform_init
 */
void sm_init()
{
  platform_init();
}

//Init the monitor organized memory.
uintptr_t sm_mm_init(uintptr_t paddr, uintptr_t size)
{
  uintptr_t retval = 0;

  retval = mm_init(paddr, size);

  return retval;
}

//Extand the monitor organized memory.
uintptr_t sm_mm_extend(uintptr_t paddr, uintptr_t size)
{
  uintptr_t retval = 0;

  retval = mm_init(paddr, size);

  return retval;
}

uintptr_t pt_area_base = 0;
uintptr_t pt_area_size = 0;
uintptr_t pt_area_end = 0;
uintptr_t mbitmap_base = 0;
uintptr_t mbitmap_size = 0;
uintptr_t pgd_order = 0;
uintptr_t pmd_order = 0;
uintptr_t pt_area_pmd_base = 0;
uintptr_t pt_area_pte_base = 0;
spinlock_t mbitmap_lock = SPINLOCK_INIT;

/**
 * \brief This function validates whether the enclave environment is ready
 * It will check the PT_AREA and MBitmap.
 * If the two regions are properly configured, it means the host OS
 * has invoked SM_INIT sbi call and everything to run enclave is ready.
 *
 */
int enable_enclave()
{
  return pt_area_base && pt_area_size && mbitmap_base && mbitmap_size;
}

/**
 * \brief Init the bitmap, set the bitmap memory as the secure memory.
 *
 * \param _mbitmap_base The start address of the bitmap.
 * \param _mbitmap_size The bitmap memory size.
 */
int init_mbitmap(uintptr_t _mbitmap_base, uintptr_t _mbitmap_size)
{
  page_meta* meta = (page_meta*)_mbitmap_base;
  uintptr_t cur = 0;
  while(cur < _mbitmap_size)
  {
    *meta = MAKE_PUBLIC_PAGE(NORMAL_PAGE);
    meta += 1;
    cur += sizeof(page_meta);
  }

  return 0;
}

/**
 * \brief Check whether the pfn range contains the secure memory.
 *
 * \param pfn The start page frame.
 * \param pagenum The page number in the pfn range.
 */
int contain_private_range(uintptr_t pfn, uintptr_t pagenum)
{
  if(!enable_enclave())
    return 0;

  if(pfn < ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT)){
    sbi_bug("M mode: contain_private_range: pfn is out of the DRAM range\n");
    return -1;
  }

  pfn = pfn - ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT);
  page_meta* meta = (page_meta*)mbitmap_base + pfn;
  if((uintptr_t)(meta + pagenum) > (mbitmap_base + mbitmap_size)){
    sbi_bug("M mode: contain_private_range: meta is out of the mbitmap range\n");
    return -1;
  }

  uintptr_t cur = 0;
  while(cur < pagenum)
  {
    if(IS_PRIVATE_PAGE(*meta))
      return 1;
    meta += 1;
    cur += 1;
  }

  return 0;
}

/**
 * \brief The function checks whether a range of physical memory is untrusted memory (for 
 *  Host OS/apps to use)
 * Return value:
 * 	-1: some pages are not public (untrusted)
 * 	 0: all pages are public (untrusted).
 *
 * \param pfn The start page frame.
 * \param pagenum The page number in the pfn range.
 */
inline int test_public_range(uintptr_t pfn, uintptr_t pagenum)
{
  if(unlikely(pfn < ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT))){
    sbi_bug("M mode: test_public_range: pfn is out of DRAM range\n");
    return -1;
  }

  pfn = pfn - ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT);
  page_meta* meta = (page_meta*)mbitmap_base + pfn;
  if(unlikely((uintptr_t)(meta + pagenum) > (mbitmap_base + mbitmap_size))){
    sbi_bug("M mode: test_public_range: meta is out of range\n");
    return -1;
  }

  uintptr_t cur = 0;
  while(cur < pagenum)
  {
    if(unlikely(!IS_PUBLIC_PAGE(*meta))){
      sbi_bug("M mode: test_public_range: IS_PUBLIC_PAGE is failed\n");
      return -1;
    }
    meta += 1;
    cur += 1;
  }

  return 0;
}

/**
 * \brief This function will set a range of physical pages, [pfn, pfn+pagenum],
 *  to secure pages (or private pages).
 * This function only updates the metadata of physical pages, but not unmap
 * them in the host PT pages.
 * Also, the function will not check whether a page is already secure.
 * The caller of the function should be careful to perform the above two tasks.
 *
 * \param pfn The start page frame.
 * \param pagenum The page number in the pfn range.
 */
int set_private_range(uintptr_t pfn, uintptr_t pagenum)
{
  if(!enable_enclave())
    return 0;

  if(pfn < ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT))
    return -1;

  pfn = pfn - ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT);
  page_meta* meta = (page_meta*)mbitmap_base + pfn;
  if((uintptr_t)(meta + pagenum) > (mbitmap_base + mbitmap_size))
    return -1;

  uintptr_t cur = 0;
  while(cur < pagenum)
  {
    *meta = MAKE_PRIVATE_PAGE(*meta);
    meta += 1;
    cur += 1;
  }

  return 0;
}

/**
 * \brief Similiar to set_private_pages, but set_public range turns a set of pages
 *  into public (or untrusted).
 *
 * \param pfn The start page frame.
 * \param pagenum The page number in the pfn range.
 */
int set_public_range(uintptr_t pfn, uintptr_t pagenum)
{
  if(!enable_enclave())
    return 0;

  if(pfn < ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT))
    return -1;

  pfn = pfn - ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT);
  page_meta* meta = (page_meta*)mbitmap_base + pfn;
  if((uintptr_t)(meta + pagenum) > (mbitmap_base + mbitmap_size))
    return -1;

  uintptr_t cur = 0;
  while(cur < pagenum)
  {
    *meta = MAKE_PUBLIC_PAGE(*meta);
    meta += 1;
    cur += 1;
  }

  return 0;
}

/**
 * \brief Init the schrodinger page. Check whether can mark these pages as schrodinger page.
 *
 * \param paddr The start page frame.
 * \param size The page number in the pfn range.
 */
uintptr_t sm_schrodinger_init(uintptr_t paddr, uintptr_t size)
{
  int ret = 0;
  if(!enable_enclave())
    return 0;

  if(paddr & (RISCV_PGSIZE-1) || !(paddr >= (uintptr_t)DRAM_BASE
        /*&& paddr + size <= (uintptr_t)DRAM_BASE + */))
    return -1;

  if(size < RISCV_PGSIZE || size & (RISCV_PGSIZE-1))
    return -1;

  spin_lock(&mbitmap_lock);

  uintptr_t pagenum = size >> RISCV_PGSHIFT;
  uintptr_t pfn = PADDR_TO_PFN(paddr);
  if(test_public_range(pfn, pagenum) != 0)
  {
    ret = -1;
    goto out;
  }

  //fast path
  uintptr_t _pfn = pfn - ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT);

  //slow path
  uintptr_t *pte = (uintptr_t*)pt_area_base;
  uintptr_t pte_pos = 0;
  uintptr_t *pte_end = (uintptr_t*)(pt_area_end);
  uintptr_t pfn_base = PADDR_TO_PFN((uintptr_t)DRAM_BASE) + _pfn;
  uintptr_t pfn_end = PADDR_TO_PFN(paddr + size);
  //check whether these page only has one mapping in the kernel
  //pte @ pt entry address
  //pfn @ the pfn in the current pte
  //pte_pos @ the offset begin the pte and pt_area_base
  while(pte < pte_end)
  {
    if(!IS_PGD(*pte) && PTE_VALID(*pte))
    {
      pfn = PTE_TO_PFN(*pte);
      //huge page entry
      if( ((unsigned long)pte >= pt_area_pmd_base) && ((unsigned long)pte < pt_area_pte_base)
      &&IS_LEAF_PTE(*pte))
      {
        //the schrodinger page is large than huge page
        if(((pfn_base<pfn) && (pfn<pfn_end) && (pfn_end>pfn) && (pfn_end<(pfn+RISCV_PTENUM))) 
            || ((pfn_base<(pfn+RISCV_PTENUM)) && ((pfn+RISCV_PTENUM)<pfn_end) && (pfn_base>pfn) && (pfn_base<(pfn+RISCV_PTENUM))))
        {
          sbi_bug(" M mode: ERROR: schrodinger_init: non-split page\n");
          return -1;
        }
      }
    }
    pte_pos += 1;
    pte += 1;
  }
out:
  spin_unlock(&mbitmap_lock);
  return ret;
}

int sm_count = 0;
/**
 * \brief Auxiliary function for debug.
 */
uintptr_t sm_print(uintptr_t paddr, uintptr_t size)
{
  sm_count++;
  return 0;
  int zero_map_num = 0;
  int single_map_num = 0;
  int multi_map_num = 0;
  uintptr_t pfn = PADDR_TO_PFN(paddr);
  uintptr_t _pfn = pfn - PADDR_TO_PFN((uintptr_t)DRAM_BASE);
  uintptr_t pagenum = size >> RISCV_PGSHIFT;
  page_meta* meta = (page_meta*)mbitmap_base + _pfn;
  uintptr_t i = 0;
  while(i < pagenum)
  {
    if(IS_ZERO_MAP_PAGE(*meta))
      zero_map_num+=1;
    else if(IS_SCHRODINGER_PAGE(*meta))
      single_map_num+=1;
    else
      multi_map_num+=1;
    i += 1;
    meta += 1;
  }
  sbi_printf("sm_print: paddr:0x%lx, zeromapnum:0x%x,singleapnum:0x%x,multimapnum:0x%x\n",
      paddr, zero_map_num, single_map_num, multi_map_num);
  return 0;
}

/**
 * \brief split the pmd entry (a huge page, 2M) into several pte entries (4K PT page)
 * 
 * \param pmd The given huge pmd entry.
 * \param new_pte_addr The new pte page address.
 */
uintptr_t sm_map_pte(uintptr_t* pmd, uintptr_t* new_pte_addr)
{
  unsigned long pte_attribute = PAGE_ATTRIBUTION(*pmd);
  unsigned long pfn = PTE_TO_PFN(*pmd);
  *pmd = PA_TO_PTE((uintptr_t)new_pte_addr, PTE_V);
  for(int i = 0; i <RISCV_PTENUM; i++)
  {
    new_pte_addr[i] = PFN_TO_PTE((pfn + i), pte_attribute);
  }
  return 0;
}

/**
 * \brief Unmap a memory region, [paddr, paddr + size], from host's all PTEs
 * (remove) We can achieve a fast path unmapping if the unmapped pages are SCHRODINGER PAGEs.
 * 
 * \param paddr The unmap memory address.
 * \param size The unmap memory size.
 */
int unmap_mm_region(unsigned long paddr, unsigned long size)
{
  if(!enable_enclave())
    return 0;

  if(paddr < (uintptr_t)DRAM_BASE /*|| (paddr + size) > */){
    sbi_bug("M mode: unmap_mm_region: paddr is less than DRAM_BASE\n");
    return -1;
  }

  uintptr_t pfn_base = PADDR_TO_PFN(paddr);
  uintptr_t pfn_end = PADDR_TO_PFN(paddr + size);
  uintptr_t *pte = (uintptr_t*)(pt_area_pmd_base);
  uintptr_t *pte_end = (uintptr_t*)(pt_area_end);

  while(pte < pte_end)
  {
    if(!IS_PGD(*pte) && PTE_VALID(*pte))
    {
      uintptr_t pfn = PTE_TO_PFN(*pte);

      // Check for the valid huge page entry
      if(((unsigned long)pte < pt_area_pte_base)
		      && IS_LEAF_PTE(*pte))
      {
        if(pfn >= pfn_end || (pfn+RISCV_PTENUM )<= pfn_base)
        {
          //There is no  overlap between the  pmd region and remap region
          pte += 1;
          continue;
        }
        else if(pfn_base<=pfn && pfn_end>=(pfn+RISCV_PTENUM))
        {
          //This huge page is covered by remap region
          *pte = INVALIDATE_PTE(*pte);
        }
        else
        {
          sbi_bug("M mode: ERROR: unmap_mm_region: non-split page\n");
          return -1;
        }
      }
      // Check for the valid page table entry
      else if( ((unsigned long)pte >= pt_area_pte_base) 
		      && ((unsigned long)pte < pt_area_end)
		      && IS_LEAF_PTE(*pte))
      {
        if(pfn >= pfn_base && pfn < pfn_end)
        {
          *pte = INVALIDATE_PTE(*pte);
        }
      }
    }
    pte += 1;
  }

  return 0;
}

/**
 * \brief Remap a set of pages to host PTEs.
 * It's usually used when we try to free a set of secure pages.
 * 
 * \param paddr The mmap memory address.
 * \param size The mmap memory size.
 */
int remap_mm_region(unsigned long paddr, unsigned long size)
{
  if(!enable_enclave())
    return 0;

  if(paddr < (uintptr_t)DRAM_BASE /*|| (paddr + size) > */)
    return -1;

  //Slow path
  uintptr_t pfn_base = PADDR_TO_PFN(paddr);
  uintptr_t pfn_end = PADDR_TO_PFN(paddr + size);
  uintptr_t *pte = (uintptr_t*)(pt_area_pmd_base);
  uintptr_t *pte_end = (uintptr_t*)(pt_area_end);
  while(pte < pte_end)
  {
    if(!IS_PGD(*pte))
    {
      uintptr_t pfn = PTE_TO_PFN(*pte);

      // Remap the huge page entry
      if(((unsigned long)pte < pt_area_pte_base))
      {
        if(pfn >= pfn_end || (pfn+RISCV_PTENUM )<= pfn_base)
        {
          //There is no  overlap between the  pmd region and remap region
          pte += 1;
          continue;
        }
        else if(pfn_base<=pfn && pfn_end>=(pfn+RISCV_PTENUM))
        {
          //The huge page is covered by remap region
          *pte = VALIDATE_PTE(*pte);
        }
        else
        {
          sbi_bug("M mode: The partial of his huge page is belong to enclave and the rest is belong to untrusted OS\n");
          return -1;
        }
      }
      // Remap the page table entry
      else if(((unsigned long)pte >= pt_area_pte_base) && ((unsigned long)pte < pt_area_end))
      {
        if(pfn >= pfn_base && pfn < pfn_end)
        {
          *pte = VALIDATE_PTE(*pte);
        }
      }
    }
    pte += 1;
  }

  return 0;
}

// static spinlock_t enclave_sm_lock = SPINLOCK_INIT;

/**
 * \brief Set a single pte entry. It will be triggled by the untrusted OS when setting new pte entry value.
 * 
 * \param pte_dest The location of pt entry in pt area
 * \param pte_src The content of pt entry
 */
inline int set_single_pte(uintptr_t *pte_dest, uintptr_t pte_src)
{
  *pte_dest = pte_src;
  
  return 0;
}

/**
 * \brief Check whether the page table entry located in the legitimate location (pt_area).
 * This check can be done in the hardware (extend in MMU).
 * 
 * \param pte_addr The address of the pte entry.
 * \param pte_src The value of the pte entry.
 * \param pa The physical address contained in the pte entry.
 */
inline int check_pt_location(uintptr_t pte_addr, uintptr_t pa, uintptr_t pte_src)
{
  if (pa == 0)
    return 0;
  if((pt_area_base < pte_addr) && ((pt_area_pmd_base) > pte_addr))
  {
    if(((pt_area_pmd_base) > pa) || ((pt_area_pte_base) < pa) )
    {
      sbi_printf("pt_area_base %lx pte_addr %lx pa %lx\n", pt_area_base, pte_addr, pa);
      sbi_bug("M mode: invalid pt location\n");
      return -1;
    }
  }
  if(((pt_area_pmd_base) < pte_addr) && ((pt_area_pte_base) > pte_addr))
  {
    if((pte_src & PTE_V) && !(pte_src & PTE_R) && !(pte_src & PTE_W) && !(pte_src & PTE_X))
    {
      if (((pt_area_pte_base) > pa) || ((pt_area_end) < pa) )
      {
        sbi_printf("pt_area_base %lx pt_area_pte_base %lx pt_area_pte_end %lx pte_addr %lx pa %lx\n", pt_area_base, (pt_area_pte_base), 
        (pt_area_end), pte_addr, pa);
        sbi_bug("M mode: invalid pt location\n");
        return -1;
      }
    }
  }
  return 0;
}

/**
 * \brief Check whether it is a huge page table entry.
 * 
 * \param pte_addr The address of the pte entry.
 * \param pte_src The value of the pte entry.
 * \param pa The physical address contained in the pte entry.
 * \param page_num Return value. Huge page entry: 512, otherwise: not change.
 */
inline int check_huge_pt(uintptr_t pte_addr, uintptr_t pa, uintptr_t pte_src, int *page_num)
{
  if(unlikely(((pt_area_pmd_base) < pte_addr) && ((pt_area_pte_base) > pte_addr)))
  {
    if((pte_src & PTE_V) && ((pte_src & PTE_R) || (pte_src & PTE_W) || (pte_src & PTE_X)))
    {
      *page_num = RISCV_PTENUM;
    }
  }
  return 0;
}

/**
 * \brief Set and check a single pte entry.
 * 
 * \param pte_dest The location of pt entry in pt area
 * \param pte_src The content of pt entry
 */
inline int set_check_single_pte(uintptr_t *pte_addr, uintptr_t pte_src, int pte_num)
{
  int ret = 0;
  if(likely((!IS_PGD(pte_src)) && PTE_VALID(pte_src)))
  {
    uintptr_t pfn = PTE_TO_PFN(pte_src);
    if (unlikely(check_pt_location((uintptr_t)pte_addr, PTE_TO_PA(pte_src), pte_src) < 0))
    {
      ret = -1;
      sbi_bug("M mode: sm_set_pte: SBI_SET_PTE_ONE: check_pt_location is failed \n");
    }
    if(unlikely(test_public_range(pfn, pte_num) < 0))
    {
      ret = -1;
      sbi_bug("M mode: sm_set_pte: SBI_SET_PTE_ONE: test_public_range is failed \n");
    }
  }
  set_single_pte(pte_addr, pte_src);
  
  return ret;
}

/**
 * \brief Set pte entry. It will be triggered by the untrusted OS when writing pte entry (set, copy, clear, etc).
 * Before setting the pte entry, check whether the mapped page is non secure (in the public range).
 * 
 * \param pte_addr The location of pt entry in pt area.
 * \param pte_src The content of pt entry.
 * \param flag The page entry flag.
 * \param size The total pte entries size.
 */
uintptr_t sm_set_pte(uintptr_t flag, uintptr_t* pte_addr, uintptr_t pte_src, uintptr_t size)
{
  unsigned long ret = 0;
  int pte_num = 1;
  
  check_huge_pt((uintptr_t)pte_addr, PTE_TO_PA(pte_src), pte_src, &pte_num);
  spin_lock(&mbitmap_lock);
  switch(flag)
  {
    case SBI_SET_PTE_ONE:
      if ((ret = set_check_single_pte(pte_addr, pte_src, pte_num)) != 0)
        goto free_mbitmap_lock;
      break;
    case SBI_PTE_MEMSET:
      if (unlikely(pte_src != 0 ))
      {
        ret = -1;
        sbi_bug("M mode: sm_set_pte: SBI_PTE_MEMSET: pte src value is not zero \n");
        goto free_mbitmap_lock;
      }
      uintptr_t i1 = 0;
      for(i1 = 0; i1 < size/sizeof(uintptr_t); ++i1, ++pte_addr)
      {
        set_single_pte(pte_addr, pte_src);
      }
      break;
    case SBI_PTE_MEMCPY:
      if(size % 8)
      {
        ret = -1;
        sbi_bug("M mode: sm_set_pte: SBI_PTE_MEMCPY: size align is failed \n");
        goto free_mbitmap_lock;
      }
      unsigned long i=0, pagenum=size>>3;
      for(i=0; i<pagenum; ++i)
      {
        uintptr_t pte = *((uintptr_t*)pte_src + i);
        if(!IS_PGD(pte) && PTE_VALID(pte))
        {
          if(test_public_range(PTE_TO_PFN(pte),pte_num) < 0)
          {
            ret =-1;
            sbi_bug("M mode: sm_set_pte: SBI_PTE_MEMCPY: test_public_range is failed \n");
            goto free_mbitmap_lock;
          }
        }
      }
      //sbi_memcpy(pte_addr, (char*)pte_src, size);
      for(i = 0; i< pagenum; ++i, ++pte_addr)
      {
        uintptr_t pte = *((uintptr_t*)pte_src + i);
        if (unlikely(check_pt_location((uintptr_t)pte_addr, PTE_TO_PA(pte), pte) < 0))
        {
          ret = -1;
          sbi_bug("M mode: sm_set_pte: SBI_PTE_MEMCPY: check_pt_location is failed \n");
        }
        set_single_pte(pte_addr, pte);
      }
      break;
    case SBI_SET_PTE_BATCH_ZERO:
    {
      uintptr_t index = pte_src;
      // FIXME: 
      // Check whether pt_area_batch is a legal pointer
      struct pt_area_batch_t * pt_area_batch = (struct pt_area_batch_t *)pte_addr;
      uintptr_t i, single_pte_addr;

      for (i = 0; i < index; i++)
      {
        for (single_pte_addr = pt_area_batch[i].ptep_base; single_pte_addr < pt_area_batch[i].ptep_base+pt_area_batch[i].entity.ptep_size; single_pte_addr+=8)
        {
          if (unlikely((ret = set_check_single_pte((uintptr_t *)single_pte_addr, 0, pte_num)) != 0))
          {
            sbi_bug("M mode: sm_set_pte: SBI_SET_PTE_BATCH_ZERO: check pte entry is failed\n");
            goto free_mbitmap_lock;
          }
        }
      }
      break;
    }
    case SBI_SET_PTE_BATCH_SET:
    {
      uintptr_t index = pte_src;
      // FIXME: 
      // Check whether pt_area_batch is a legal pointer
      struct pt_area_batch_t * pt_area_batch = (struct pt_area_batch_t *)pte_addr;
      uintptr_t i, single_pte_addr;

      for (i = 0; i < index; i++)
      {
        single_pte_addr = pt_area_batch[i].ptep_base;
        if (unlikely((ret = set_check_single_pte((uintptr_t *)single_pte_addr, pt_area_batch[i].entity.ptep_entry, pte_num)) != 0))
        {
          sbi_bug("M mode: sm_set_pte: SBI_SET_PTE_BATCH_SET: check pte entry is failed\n");
          goto free_mbitmap_lock;
        }
      }
      break;
    }
    default:
      ret = -1;
      break;
  }

free_mbitmap_lock:
  spin_unlock(&mbitmap_lock);
  return ret;
}

/**
 * \brief Check the pt_area mapping when install the enclave driver
 * Ensure the page table is legitimate befor GPT is enable
 * This check can be done in the hardware (extend in MMU).
 * 
 * \param pt_area_pgd_base The base address of pgd_sub_area.
 * \param pt_area_pmd_base The base address of pmd_sub_area.
 * \param pt_area_pte_base The base address of pte_sub_area.
 * \param pt_area_end The base address of pte_sub_area.
 */
int check_pt_area_mapping(uintptr_t pt_area_pgd_base, uintptr_t pt_area_pmd_base, 
    uintptr_t pt_area_pte_base, uintptr_t pt_area_end)
{
  int ret = 0;
  
  pte_t *pte = (uintptr_t*)(pt_area_pgd_base);
  pte_t *pte_end = (uintptr_t*)(pt_area_pmd_base);

  while(pte < pte_end)
  {
    if(!IS_PGD(*pte) && PTE_VALID(*pte))
    {
      pte_t* next_page_table;
      next_page_table = (pte_t*) (pte_ppn(*pte) << RISCV_PGSHIFT);

      if (((uintptr_t)next_page_table<pt_area_pmd_base) || ((uintptr_t)next_page_table>pt_area_pte_base))
      {
        sbi_bug("M mode: check_pt_area_mapping: next_page_table %lx, pt_area_pmd_base %lx pt_area_pte_base %lx\n", 
                  (uintptr_t)next_page_table, pt_area_pmd_base, pt_area_pte_base);
        return -1;
      }
           
      ret = __check_mapping(next_page_table, pt_area_pgd_base, pt_area_pmd_base, pt_area_pte_base, 
                          pt_area_end, 1);
      if (ret < 0)
      {
        sbi_bug("M mode: check_pt_area_mapping: illegal pt_area mapping\n");
        return -1;
      }
    }
    pte += 1;
  }

  return ret;
}


/**
 * \brief SM_INIT: This is an SBI call provided by monitor
 *  The Host OS can invoke the call to init the enclave enviroment, with two regions: [pt_area_base, pt_area_base + area_size]
 *  and [mbitmap_base + mbitmap_size].
 *  The first region is PT AREA in penglai, which includes all possible PT pages used for address translation.
 *  The second region is for monitor to maintain metadata for each physical page (e.g., whether a page is secure/non-secure/or 
 *  Schrodinger.
 *  The two regions will be protected by PMPs, and this function will synchronize the PMP configs to other HARTs (if have).
 *
 *  The function can only be invoked once (checked by monitor).
 * 
 * \param _pt_area_base The pt area start address.
 * \param _pt_area_size The pt_area size.
 * \param _mbitmap_base The bitmap start address.
 * \param _mbitmap_size The bitmap size.
 */
uintptr_t sm_sm_init(uintptr_t _pt_area_base, uintptr_t _pt_area_size, uintptr_t _mbitmap_base, uintptr_t _mbitmap_size, uintptr_t _module_installed_ptr)
{
  if(pt_area_base && pt_area_size && mbitmap_base && mbitmap_size)
  {
    sbi_bug("M MODE: sm_sm_init: param is not existed\n");
    return -1UL;
  }
  uintptr_t smregion_base = (uintptr_t)SM_BASE;
  uintptr_t smregion_size = (uintptr_t)SM_SIZE;
  if(region_overlap(_pt_area_base, _pt_area_size, smregion_base, smregion_size))
  {
    sbi_bug("M MODE: sm_sm_init: region_overlap1 check failed\n");
    return -1UL;
  }
  if(region_overlap(_mbitmap_base, _mbitmap_size, smregion_base, smregion_size))
  {
    sbi_bug("M MODE: sm_sm_init: region_overlap2 check failed\n");
    return -1UL;
  }
  if(region_overlap(_pt_area_base, _pt_area_size, _mbitmap_base, _mbitmap_size))
  {
    sbi_bug("M MODE: sm_sm_init: region_overlap3 check failed\n");
    return -1UL;
  }
  if(illegal_pmp_addr(_pt_area_base, _pt_area_size) || illegal_pmp_addr(_mbitmap_base, _mbitmap_size))
  {
    sbi_bug("M MODE: sm_sm_init: region_overlap4 check failed\n");
    return -1UL;
  }

  struct pmp_config_t pmp_config;
  pmp_config.paddr = _mbitmap_base;
  pmp_config.size = _mbitmap_size;
  pmp_config.perm = PMP_NO_PERM;
  pmp_config.mode = PMP_A_NAPOT;
  //pmp 2 is used to protect mbitmap
  set_pmp_and_sync(2, pmp_config);
  //should protect mbitmap before initializing it
  init_mbitmap(_mbitmap_base, _mbitmap_size);
  //enable pt_area and mbitmap
  //this step must be after initializing mbitmap
  pt_area_size = _pt_area_size;
  pt_area_base = _pt_area_base;
  mbitmap_base = _mbitmap_base;
  mbitmap_size = _mbitmap_size;

  pmp_config.paddr = _pt_area_base;
  pmp_config.size = _pt_area_size;
  pmp_config.perm = PMP_R;
  pmp_config.mode = PMP_A_NAPOT;
  //pmp 3 is used to protect pt_area
  //this step must be after enabling pt_area and mbitmap
  set_pmp_and_sync(1, pmp_config);
  *(int *)_module_installed_ptr = 1;
  return 0;
}

/**
 * \brief This function sets the order of the pgd and pmd sub-area, and enable the TVM trap.
 * 
 * \param tmp_pgd_order The order of the pgd area page 
 * \param tmp_pmd_order The prder of the pt_area page.
 */
uintptr_t sm_pt_area_separation(uintptr_t tmp_pgd_order, uintptr_t tmp_pmd_order)
{
  pgd_order = tmp_pgd_order;
  pmd_order = tmp_pmd_order;
  pt_area_pmd_base = pt_area_base + (1<<pgd_order)*RISCV_PGSIZE;
  pt_area_pte_base = pt_area_base + (1<<pgd_order)*RISCV_PGSIZE + (1<<pmd_order)*RISCV_PGSIZE;
  pt_area_end = pt_area_base + pt_area_size;
  uintptr_t mstatus = csr_read(CSR_MSTATUS);
  /* Enable TVM here */
  mstatus = INSERT_FIELD(mstatus, MSTATUS_TVM, 1);
  csr_write(CSR_MSTATUS, mstatus);
  if (check_pt_area_mapping(pt_area_base, pt_area_pmd_base, pt_area_pte_base, pt_area_end))
  {
    sbi_bug("M MODE: sm_pt_area_separation: check pt_area mapping is failed\n");
    return -1UL;
  }
  set_tvm_and_sync();
  return 0;
}

/**
 * \brief This transitional function is used to create the enclave.
 * 
 * \param enclave_sbi_param The enclave create arguments.
 */
uintptr_t sm_create_enclave(uintptr_t enclave_sbi_param)
{
  enclave_create_param_t enclave_sbi_param_local;
  uintptr_t retval = 0;
  if(test_public_range(PADDR_TO_PFN(enclave_sbi_param),1) < 0){
    return ENCLAVE_ERROR;
  }

  retval = copy_from_host(&enclave_sbi_param_local,
      (enclave_create_param_t*)enclave_sbi_param,
      sizeof(enclave_create_param_t));
  if(retval != 0)
    return ENCLAVE_ERROR;

  retval = create_enclave(enclave_sbi_param_local);

  return retval;
}

/**
 * \brief This transitional function is used to attest the enclave.
 * 
 * \param eid The enclave id.
 * \param report The enclave measurement report.
 * \param nouce The attestation nonce.
 */
uintptr_t sm_attest_enclave(uintptr_t eid, uintptr_t report, uintptr_t nonce)
{
  uintptr_t retval;

  retval = attest_enclave(eid, report, nonce);

  return retval;
}

/**
 * \brief This transitional function is used to run an enclave.
 * 
 * \param eid The enclave id.
 * \param report The enclave measurement report.
 * \param nouce The attestation nonce.
 */
uintptr_t sm_run_enclave(uintptr_t* regs, uintptr_t eid, uintptr_t enclave_run_args)
{
  uintptr_t retval = 0;
  enclave_run_param_t enclave_sbi_param_local;

  if(test_public_range(PADDR_TO_PFN(enclave_run_args), 1) < 0){
    return ENCLAVE_ERROR;
  }
  retval = copy_from_host(&enclave_sbi_param_local,
      (enclave_run_param_t*)enclave_run_args,
      sizeof(enclave_run_param_t));

  if(retval != 0)
    return ENCLAVE_ERROR;

  retval = run_enclave(regs, (unsigned int)eid, enclave_sbi_param_local);
  sbi_printf("[sm] run_enclave return!\n");
  return retval;
}

/**
 * \brief This transitional function is used to stop the enclave.
 * 
 * \param regs The host regs.
 * \param eid The enclave id.
 */
uintptr_t sm_stop_enclave(uintptr_t* regs, uintptr_t eid)
{
  uintptr_t retval = 0;

  retval = stop_enclave(regs, (unsigned int)eid);

  return retval;

}

/**
 * \brief This transitional function is used to resume the enclave.
 * 
 * \param regs The host regs.
 * \param eid The enclave id.
 */
uintptr_t sm_resume_enclave(uintptr_t* regs, uintptr_t eid, uintptr_t resume_func_id)
{
  uintptr_t retval = 0;
  switch(resume_func_id)
  {
    case RESUME_FROM_REQUEST:
      retval = resume_from_request(regs, eid);
      break;
    case RESUME_FROM_TIMER_IRQ:
      retval = resume_enclave(regs, eid);
      break;
    case RESUME_FROM_STOP:
      retval = wake_enclave(regs, eid);
      break;
    case RESUME_FROM_OCALL:
      retval = resume_from_ocall(regs, eid);
      break;
    default:
      break;
  }

  return retval;
}

/**
 * \brief This transitional function is used to destroy the enclave.
 * 
 * \param regs The host regs.
 * \param enclave_eid The enclave id.
 */
uintptr_t sm_destroy_enclave(uintptr_t *regs, uintptr_t enclave_id)
{
  //TODO
  uintptr_t ret = 0;

  ret = destroy_enclave(regs, enclave_id);

  return ret;
}

/**************************************************************/
/*                   Interfaces for Privileged Enclave        */
/**************************************************************/
/**
 * \brief This transitional function is used to inspect the enclave.
 * 
 * \param tgt_eid The inspectee eid. (slab-layer)
 * \param src_eid The inspector eid. (slab-layer)
 * \param inspect_addr The start VA address of inspectee region
 * \param inspect_size The size of inspectee region (<= PAGE SIZE, normally 4kB)
 */
uintptr_t sm_inspect_enclave(uintptr_t tgt_eid, uintptr_t src_eid, uintptr_t inspect_addr, uintptr_t inspect_size)
{
  uintptr_t retval = 0;
  retval = inspect_enclave(tgt_eid, src_eid, inspect_addr, inspect_size); 
  return retval;
}

/**
 * \brief This transitional function is used to response the enclave.
 * 
 * \param tgt_eid The NE eid. (slab-layer)
 * \param src_eid The PE eid. (slab-layer)
 * \param response_arg The start VA address of PE's response arg.
 */
uintptr_t sm_response_enclave(uintptr_t tgt_eid, uintptr_t src_eid, uintptr_t response_arg)
{
  uintptr_t retval = 0;
  retval = response_enclave(tgt_eid, src_eid, response_arg);
  return retval;
}
/**************************************************************/
/*                   Interfaces for shadow enclave           */
/**************************************************************/
/**
 * \brief This transitional function is used to attest the shadow enclave.
 * 
 * \param eid The shadow enclave id.
 * \param report The shadow enclave measurement report.
 * \param nouce The attestation nonce.
 */
uintptr_t sm_attest_shadow_enclave(uintptr_t eid, uintptr_t report, uintptr_t nonce)
{
  uintptr_t retval;

  retval = attest_shadow_enclave(eid, report, nonce);

  return retval;
}

/**
 * \brief This transitional function is used to create the shadow enclave.
 * 
 * \param enclave_sbi_param The arguments for creating the shadow enclave.
 */
uintptr_t sm_create_shadow_enclave(uintptr_t enclave_sbi_param)
{
  enclave_create_param_t enclave_sbi_param_local;
  uintptr_t retval = 0;
  if(test_public_range(PADDR_TO_PFN(enclave_sbi_param),1) < 0){
    return ENCLAVE_ERROR;
  }
  retval = copy_from_host(&enclave_sbi_param_local,
      (enclave_create_param_t*)enclave_sbi_param,
      sizeof(enclave_create_param_t));
  if(retval != 0)
    return ENCLAVE_ERROR;

  retval = create_shadow_enclave(enclave_sbi_param_local);

  return retval;
}

/**
 * \brief This transitional function is used to run the shadow enclave.
 * 
 * \param regs The host regs.
 * \param eid The shadow enclave id.
 * \param shadow_enclave_run_args The arguments for running the shadow enclave.
 * \param mm_arg_addr The relay page address.
 * \param mm_arg_size The relay page size.
 */
uintptr_t sm_run_shadow_enclave(uintptr_t* regs, uintptr_t eid, uintptr_t shadow_enclave_run_args)
{
  shadow_enclave_run_param_t enclave_sbi_param_local;
  uintptr_t retval = 0;
  if(test_public_range(PADDR_TO_PFN(shadow_enclave_run_args), 1) < 0){
    return ENCLAVE_ERROR;
  }
  retval = copy_from_host(&enclave_sbi_param_local,
      (shadow_enclave_run_param_t*)shadow_enclave_run_args,
      sizeof(shadow_enclave_run_param_t));
  if(retval != 0)
    return ENCLAVE_ERROR;

  retval = run_shadow_enclave(regs, (unsigned int)eid, enclave_sbi_param_local);
  if (retval ==  ENCLAVE_ATTESTATION)
  {
    copy_to_host((shadow_enclave_run_param_t*)shadow_enclave_run_args,
      &enclave_sbi_param_local,
      sizeof(shadow_enclave_run_param_t));
  }
  return retval;
}

/**
 * \brief This transitional function is used to destroy the shadow enclave.
 * 
 * \param enclave_sbi_param The arguments for destroying the shadow enclave.
 */
uintptr_t sm_destroy_shadow_enclave(uintptr_t *regs, uintptr_t enclave_id)
{
  //TODO
  uintptr_t ret = 0;

  ret = destroy_shadow_enclave(regs, enclave_id);

  return ret;
}

/**************************************************************/
/*                   called by enclave                        */
/**************************************************************/
/**
 * \brief This transitional function is used to exit the enclave mode.
 * 
 * \param regs The enclave regs.
 * \param retval The enclave return value.
 */
uintptr_t sm_exit_enclave(uintptr_t* regs, uintptr_t retval)
{
  uintptr_t ret = 0;

  ret = exit_enclave(regs, retval);
  return ret;
}

/**
 * \brief This transitional function is used to handle the enclave ocall function.
 * 
 * \param regs The enclave reg.
 * \param ocall_id The ocall function id.
 * \param arg0 The ocall argument 0.
 * \param arg1 The ocall argument 1.
 */
uintptr_t sm_enclave_ocall(uintptr_t* regs, uintptr_t ocall_id, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2)
{
  uintptr_t ret = 0;

  switch(ocall_id)
  {
    case OCALL_MMAP:
      ret = enclave_mmap(regs, arg0, arg1);
      if(ret == -1UL && check_in_enclave_world() == 0)
      {
        ret = 0;
      }
      break;
    case OCALL_UNMAP:
      ret = enclave_unmap(regs, arg0, arg1);
      break;
    case OCALL_SYS_WRITE:
      ret = enclave_sys_write(regs);
      break;
    case OCALL_SBRK:
      ret = enclave_sbrk(regs, arg0);
      break;
    case OCALL_READ_SECT:
      ret = enclave_read_sec(regs,arg0);
      break;
    case OCALL_WRITE_SECT:
      ret = enclave_write_sec(regs, arg0);
      break;
    case OCALL_RETURN_RELAY_PAGE:
      sbi_printf("[sm] into sm_enclave_ocall[%ld]\n", ocall_id);
      sbi_printf("[sm] into enclave_return_relay_page\n");
      ret = enclave_return_relay_page(regs);
      sbi_printf("[sm] out enclave_return_relay_page\n");
      break;
    case OCALL_SHM_GET:
      ret = enclave_shmget(regs, arg0, arg1, arg2);
      if(ret == -1UL && check_in_enclave_world() == 0)
      {
        ret = 0;
      }   
      break;
    case OCALL_SHM_DETACH:
      ret = enclave_shmdetach(regs, arg0);
      break;
    case OCALL_SHM_DESTROY:
      ret = enclave_shmdestroy(regs, arg0);
      break;
    case OCALL_GETRANDOM:
      ret = enclave_getrandom(regs, arg0, arg1);
      break;
    /* add our Ocall transition functions here. */
    case OCALL_CREATE_ENCLAVE:
      // the arg0 is the VA of create_arg
      ret = privil_create_enclave(regs, arg0);
      break;
    case OCALL_ATTEST_ENCLAVE:
      // the arg0 is the VA of attest_arg
      ret = privil_attest_enclave(regs, arg0);
      break;
    case OCALL_RUN_ENCLAVE:
      // the arg0 is the VA of run_arg
      ret = privil_run_enclave(regs, arg0);
      break;
    case OCALL_STOP_ENCLAVE:
      ret = privil_stop_enclave(regs, arg0);
      break;
    case OCALL_RESUME_ENCLAVE:
      // the arg0 is the VA of run_arg (also as resume arg)
      ret = privil_resume_enclave(regs, arg0);
      break;
    case OCALL_DESTROY_ENCLAVE:
      // the arg0 is the idr-layer eid of target enclave.
      ret = privil_destroy_enclave(regs, arg0);
      break; 
    case OCALL_INSPECT_ENCLAVE:
      ret = privil_inspect_enclave(regs, arg0);
      break; 
    case OCALL_PAUSE_ENCLAVE:
      // the arg1 is the VA of NE request arg
      ret = privil_pause_enclave(regs, arg0);
      break;
    default:
      ret = -1UL;
      break;
  }

  return ret;
}

/**
 * \brief This transitional function is used to handle the time irq triggered in the enclave.
 * 
 * \param regs The enclave regs.
 * \param mcause CSR mcause value.
 * \param mepc CSR mepc value.
 */
uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc)
{
  uintptr_t ret = 0;

  ret = do_timer_irq(regs, mcause, mepc);
  if((ret >= 0) && (ret <= SBI_LEGAL_MAX))
	{
		regs[10] = 0;
		regs[11] = ret;
	}
  return ret;
}

/**
 * \brief (remove) This transitional function is used to handle the yield() triggered in the enclave.
 * 
 * \param regs The enclave reg.
 * \param mcause CSR mcause value.
 * \param mepc CSR mepc value.
 */
uintptr_t sm_handle_yield(uintptr_t *regs)
{
  uintptr_t ret = 0;

  ret = do_yield(regs);

  return ret;
}

/**************************************************************/
/*                   Interfaces for server enclave           */
/**************************************************************/
/**
 * \brief This transitional function is used to create the server enclave.
 * 
 * \param regs The enclave regs.
 * \param mcause CSR mcause value.
 * \param mepc CSR mepc value.
 */
uintptr_t sm_create_server_enclave(uintptr_t enclave_sbi_param)
{
  enclave_create_param_t enclave_sbi_param_local;
  uintptr_t retval = 0;
  if(test_public_range(PADDR_TO_PFN(enclave_sbi_param),1)<0){
    return ENCLAVE_ERROR;
  }
  retval = copy_from_host(&enclave_sbi_param_local,
      (enclave_create_param_t*)enclave_sbi_param,
      sizeof(enclave_create_param_t));
  if(retval != 0)
    return ENCLAVE_ERROR;

  retval = create_server_enclave(enclave_sbi_param_local);

  return retval;
}

/**
 * \brief This transitional function is used to destroy the server enclave.
 * 
 * \param enclave_sbi_param The arguments for creating the server enclave.
 */
uintptr_t sm_destroy_server_enclave(uintptr_t *regs, uintptr_t enclave_id)
{
  //TODO
  uintptr_t ret = 0;

  ret = destroy_server_enclave(regs, enclave_id);

  return ret;
}

/**
 * \brief This transitional function acquires the handler of server enclave.
 * 
 * \param regs The enclave regs.
 * \param server_name The acquired server enclave name.
 */
uintptr_t sm_server_enclave_acquire(uintptr_t *regs, uintptr_t server_name)
{
  uintptr_t ret = 0;

  ret = acquire_server_enclave((char*)server_name);

  return ret;
}

/**
 * \brief Get the enclave attestation report.
 * 
 * \param regs   The enclave regs.
 * \param name   Enclave name, NULL for current enclave.
 * \param report The structure of the attestatio report.
 * \param nonce  The nonce for this attested request
 */
uintptr_t sm_get_report(uintptr_t *regs, char* name, uintptr_t *report, uintptr_t nonce)
{
  uintptr_t ret = 0;

  if (name == NULL)
    ret = get_enclave_attest_report(report, nonce);
  else
    ret = get_server_enclave_attest_report(name, report, nonce);

  return ret;
}

/**
 * \brief Retrun key to enclave.
 * 
 * \param regs      The enclave regs.
 * \param key_type  Acquired key type.
 * \param key       Received key pointer.
 * \param key_len   Received key size 
 */
uintptr_t sm_get_key(uintptr_t *regs, uintptr_t key_type, uintptr_t *key, uintptr_t key_size)
{
  uintptr_t ret = 0;

  ret = derive_key(key_type, key, key_size);

  return ret;
}

/**
 * \brief This transitional function gets the caller enclave id (used in the PSA).
 * 
 * \param regs The enclave regs.
 */
uintptr_t sm_get_caller_id(uintptr_t *regs)
{
  uintptr_t ret = 0;

  ret = get_caller_id(regs);

  return ret;
}

/**
 * \brief This transitional function gets the current enclave id.
 * 
 * \param regs The enclave regs.
 */
uintptr_t sm_get_enclave_id(uintptr_t *regs)
{
  uintptr_t ret = 0;

  ret = get_enclave_id(regs);

  return ret;
}

/**
 * \brief This transitional function is used to call the server enclave.
 * 
 * \param regs The enclave regs.
 * \param eid The callee enclave id.
 * \param arg The calling arguments.
 */
uintptr_t sm_call_enclave(uintptr_t* regs, uintptr_t eid, uintptr_t arg)
{
  uintptr_t retval = 0;

  retval = call_enclave(regs, (unsigned int)eid, arg);

  return retval;
}

/**
 * \brief This transitional function is used for server enclave return .
 * 
 * \param regs The enclave regs.
 * \param arg The return arguments.
 */
uintptr_t sm_enclave_return(uintptr_t* regs, uintptr_t arg)
{
  uintptr_t ret = 0;

  ret = enclave_return(regs, arg);

  return ret;
}

/**
 * \brief This transitional function is used to invoke an asynchronous enclave call to the server enclave.
 * 
 * \param regs The enclave regs.
 * \param enclave_name The callee enclave name.
 * \param arg The calling arguments.
 */
uintptr_t sm_asyn_enclave_call(uintptr_t *regs, uintptr_t enclave_name, uintptr_t arg)
{
  uintptr_t ret = 0;

  ret = asyn_enclave_call(regs, enclave_name, arg);
  return ret;
}

/**
 * \brief This transitional function splits the relay page memory into two regions.
 * 
 * \param regs The enclave regs.
 * \param mem_addr The relay page physical address
 * \param mem_size The size of relay pages.
 * \param split_addr The splitted point in the relay pages.
 */
uintptr_t sm_split_mem_region(uintptr_t *regs, uintptr_t mem_addr, uintptr_t mem_size, uintptr_t split_addr)
{
  uintptr_t ret = 0;

  ret = split_mem_region(regs, mem_addr, mem_size, split_addr);

  return ret;
}