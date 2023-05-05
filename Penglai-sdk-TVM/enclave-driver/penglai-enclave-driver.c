#include <linux/mm.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/pt_area.h>
#include <asm/sbi.h>
#include "penglai-enclave-driver.h"
#include "penglai-enclave-ioctl.h"
#include "penglai-schrodinger.h"
#include "riscv64.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("enclave_ioctl");
MODULE_AUTHOR("LuXu");
MODULE_VERSION("enclave_ioctl");

DEFINE_SPINLOCK(enclave_get_free_page_lock);

extern char *pt_area_vaddr;
extern unsigned long pt_area_pages;

extern int PGD_PAGE_ORDER;
extern int PMD_PAGE_ORDER;

extern int enclave_module_installed;

void penglai_scan_huge_page_entry(unsigned long paddr, unsigned long size, struct pt_entry_t * split_pmd)
{
  unsigned long pfn_base = PADDR_TO_PFN(paddr);
  unsigned long pfn_end = PADDR_TO_PFN(paddr + size);
  unsigned long *pte = (unsigned long*)(pt_area_vaddr + (1<<PGD_PAGE_ORDER)*RISCV_PGSIZE);
  unsigned long *pte_end = (unsigned long*)(pt_area_vaddr + (1<<PGD_PAGE_ORDER)*RISCV_PGSIZE + (1<<PMD_PAGE_ORDER)*RISCV_PGSIZE);
  while(pte < pte_end)
  {
    if(!IS_PGD(*pte) && PTE_VALID(*pte))
    {
      unsigned long pfn = PTE_TO_PFN(*pte);
      if(IS_LEAF_PTE(*pte))
      {
        if(pfn >= pfn_end || (pfn+512 )<= pfn_base)
        {
          //There is no  overlap between the  pmd region and remap region
          pte += 1;
          continue;
        }
        else if(pfn_base<=pfn && pfn_end>=(pfn+512))
        {
          pte += 1;
          continue;
        }
        else
        {
          split_pmd->pte_addr = (unsigned long)pte;
          split_pmd->pte = *pte;
	        break;
        }
      }
    }
    pte += 1;
  }
}

extern unsigned long va_pa_offset;
unsigned long penglai_get_free_pages(gfp_t gfp_mask, unsigned int order)
{
  unsigned long va;
  int ret;

  spin_lock(&enclave_get_free_page_lock);
  va = __get_free_pages(gfp_mask, order);
  spin_unlock(&enclave_get_free_page_lock);

  if (order < 9 )
  {
    struct pt_entry_t split_pte;
    char * new_pt_pte_page;
    char scan_huge_pt = 1;
    split_pte.pte = 0;
    split_pte.pte_addr = 0;
    spin_lock(&enclave_get_free_page_lock);
    while (scan_huge_pt) {
      penglai_scan_huge_page_entry(__pa(va), (1<<order)*RISCV_PGSIZE, &split_pte);
      if (split_pte.pte_addr != 0)
      {
        new_pt_pte_page = alloc_pt_pte_page();
        ret = SBI_PENGLAI_2(SBI_SM_MAP_PTE, __pa(split_pte.pte_addr), __pa(new_pt_pte_page));
        split_pte.pte = 0;
        split_pte.pte_addr = 0;
      }
      else {
        scan_huge_pt = 0;
      }
    }
    spin_unlock(&enclave_get_free_page_lock);
  }
  return va;
}

static int dev_open(struct inode *inodep, struct file *filep)
{
  filep->private_data = kzalloc(sizeof(struct dev_private_data_t), GFP_KERNEL);

  if(!filep->private_data)
  {
    penglai_eprintf("dev_open: failed to allocate private_data\n");
    return -1;
  }

  return 0;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
  if(filep->private_data)
  {
    kfree(filep->private_data);
  }

  return 0;
}

static int dev_mmap(struct file* filep, struct vm_area_struct *vma)
{
  struct dev_private_data_t* dev_data = filep->private_data;
  unsigned long addr;
  if(!(dev_data->mmap_vaddr) || dev_data->mmap_size < (vma->vm_end - vma->vm_start))
  {
    penglai_eprintf("mmap: no enough data to mmap\n");
    return -1;
  }

  addr = dev_data->mmap_vaddr;
  //TODO: get_page

  if(remap_pfn_range(vma, vma->vm_start, virt_to_pfn(addr), vma->vm_end - vma->vm_start, vma->vm_page_prot))
  {
    penglai_eprintf("mmap: failed to mmap\n");
    //TODO: put_page
    return -1;
  }

  return 0;
}

static const struct file_operations enclave_ops = {
  .open = dev_open,
  .owner = THIS_MODULE,
  .mmap = dev_mmap,
  .unlocked_ioctl = penglai_enclave_ioctl,
  .release = dev_release,
};

struct miscdevice enclave_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "penglai_enclave_dev",
  .fops = &enclave_ops,
  .mode = 0666,
};

struct pt_page_list{
  //struct pt_page_list *prev_page;
  struct pt_page_list *next_page;
};

static int enclave_ioctl_init(void)
{
  int ret;
  unsigned long bitmap_bytes, bitmap_pages, order, schrodinger_addr;
  unsigned long bitmap;
  struct sysinfo s_info;
  penglai_printf("enclave_ioctl_init...\n");

  //register enclave_dev
  ret=misc_register(&enclave_dev);
  penglai_printf("enclave_dev minor %d\n", enclave_dev.minor);
  if(ret < 0)
  {
    penglai_eprintf("register enclave_dev failed!\n");
    goto deregister_device;
  }

  //allocate bitmap
  si_meminfo(&s_info);
  bitmap_bytes = s_info.totalram * sizeof(int);
  bitmap_pages = (bitmap_bytes % PAGE_SIZE) == 0 ? bitmap_bytes >> PAGE_SHIFT : (bitmap_bytes >> PAGE_SHIFT) + 1;
  order = ilog2(bitmap_pages -1) + 1;
  if (order < 9)
    order = 9;
  bitmap = penglai_get_free_pages(GFP_KERNEL, order);
  if(!bitmap)
  {
    penglai_eprintf("failed to allocate %lu page(s)\n", ((unsigned long) 0x1)<<order);
    ret = -ENOMEM;
    goto deregister_device;
  }
  bitmap_pages = 1 << order;
  memset((void *)bitmap, 0, (bitmap_pages << PAGE_SHIFT));

  penglai_printf("total %lupages, bitmap_pages need %lu, allocate %lu page(s)\n", s_info.totalram, bitmap_pages, (unsigned long)1<<order);
  
  penglai_printf("pt_area_pa %lx pt_area_va %lx pt_area_size %lx \n", __pa(pt_area_vaddr), pt_area_vaddr, pt_area_pages << PAGE_SHIFT);//broadcast to other harts
  penglai_printf("bitmap_pa %lx bitmap_va %lx bitmap_size %lx \n", __pa(bitmap), bitmap, bitmap_pages << PAGE_SHIFT);//broadcast to other harts
  penglai_printf("pa %lx\n", __pa(0xffffffe00020142c));
  ret = SBI_PENGLAI_5(SBI_SM_INIT, __pa(pt_area_vaddr), pt_area_pages << PAGE_SHIFT,
      __pa(bitmap), bitmap_pages << PAGE_SHIFT, __pa(&enclave_module_installed));

  penglai_printf("finish sm init\n");

  // pt_area is protected by the PMP now, so enclave_module is installed 
  // enclave_module_installed = 1;

  if(ret)
  {
    penglai_eprintf("failed to create mbitmap\n");
    goto free_bitmap;
  }
  ret = SBI_PENGLAI_2(SBI_SM_PT_AREA_SEPARATION, PGD_PAGE_ORDER, PMD_PAGE_ORDER);

  schrodinger_addr = penglai_get_free_pages(GFP_KERNEL, DEFAULT_SCHRODINGER_ORDER);
  memset((void *)schrodinger_addr, 0, RISCV_PGSIZE*(1<<DEFAULT_SCHRODINGER_ORDER));

  if(schrodinger_addr)
  {
    ret = schrodinger_init(schrodinger_addr, RISCV_PGSIZE * (1 << DEFAULT_SCHRODINGER_ORDER));
    if(ret != 0)
    {
      free_pages(schrodinger_addr, DEFAULT_SCHRODINGER_ORDER);
      penglai_eprintf("failed to alloc schrodinger mem\n");
      goto free_bitmap;
    }
    penglai_printf("Initialize the schrodinger page\n");

  }
  else
  {
    penglai_eprintf("failed to alloc schrodinger mem\n");
    goto free_bitmap;
  }

  penglai_printf("register_chrdev succeeded!\n");
  
  return 0;
  
free_bitmap:
  if(bitmap)
  {
    free_pages(bitmap, order);
  }

deregister_device:
  misc_deregister(&enclave_dev);
  return ret;
}

static void enclave_ioctl_exit(void)
{
  //unsigned long size, addr, order, count;
  penglai_printf("enclave_ioctl_exit...\n");
  misc_deregister(&enclave_dev);
  return;
}

module_init(enclave_ioctl_init);
module_exit(enclave_ioctl_exit);
