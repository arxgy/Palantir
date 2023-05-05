#include "sbi/sbi_console.h"
#include "sm/sm.h"
#include "sm/enclave.h"
#include "sm/enclave_vm.h"
#include "sm/server_enclave.h"
#include "sm/ipi.h"
#include "sm/enclave_mm.h"

/**************************************************************/
/*                                 called by enclave                                                        */
/**************************************************************/

/**
 * \brief Monitor is responsible for change the relay page ownership:
 * It can be divide into two phases: First  umap the relay page for caller
 * enclave, and map the relay page for subsequent enclave asynchronously.
 * Second, change the relay page ownership entry in the relay page linke memory. 
 *
 * note: the relay_page_addr_u is the virtual address of relay page. However in the relay page entry,
 * it binds the enclave name with the physical address.
 * 
 * The first enclave in the enclave call chain can only hold single relay page region (now version),
 * but can split to atmost N piece ans transfer to different enclaves. The following enclave can receive\
 * multiple relay page entry.
 * 
 * \param enclave The enclave structure.
 * \param relay_page_addr_u The relay page address.
 * \param relay_page_size The relay page size.
 * \param enclave_name_u The given enclave name.
 */
uintptr_t transfer_relay_page(struct enclave_t *enclave, unsigned long relay_page_addr_u, unsigned long relay_page_size, char *enclave_name_u)
{
  uintptr_t ret = 0;
  char *enclave_name = NULL;
  unsigned long relay_page_addr = 0;

  enclave_name = va_to_pa((uintptr_t*)(enclave->root_page_table), enclave_name_u);
  relay_page_addr = (unsigned long)va_to_pa((uintptr_t*)(enclave->root_page_table), (char *)relay_page_addr_u);
  if(!enclave_name)
  {
    ret = -1UL;
    goto failed;
  }
  //unmap the relay page for call enclave
  unmap((uintptr_t*)(enclave->root_page_table), relay_page_addr_u, relay_page_size);  
  for (int kk = 0; kk < 5; kk++)
  {
    if(enclave->mm_arg_paddr[kk] == relay_page_addr)
    {
      enclave->mm_arg_paddr[kk] = 0;
      enclave->mm_arg_size[kk] = 0;
    }
  }

  //change the relay page ownership
  if (change_relay_page_ownership((unsigned long)relay_page_addr, relay_page_size, enclave_name) < 0)
  {
    ret = -1UL;
    sbi_bug("M mode: transfer_relay_page: change relay page ownership failed\n");
  }
  return ret;
failed:
  sbi_bug("M MODE: transfer_relay_page: failed\n");
  return ret;
}

/**
 * \brief Handle the asyn enclave call. Obtain the corresponding relay page virtual address and size, and
 *  invoke the transfer_relay_page.
 *
 * \param enclave_name The callee enclave name  
 */
uintptr_t asyn_enclave_call(uintptr_t* regs, uintptr_t enclave_name, uintptr_t arg)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL;
  int eid = 0;
  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: asyn_enclave_call: CPU not in the enclave mode\n");
    return -1UL;
  }

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  release_enclave_metadata_lock();

  if(!enclave)
  {
    ret = -1UL;
    goto failed;
  }
  struct call_enclave_arg_t call_arg;
  struct call_enclave_arg_t* call_arg0 = va_to_pa((uintptr_t*)(enclave->root_page_table), (void*)arg);
  if(!call_arg0)
  {
    ret = -1UL;
    goto failed;
  }
  copy_from_host(&call_arg, call_arg0, sizeof(struct call_enclave_arg_t));
  if (transfer_relay_page(enclave, call_arg.req_vaddr, call_arg.req_size, (char *)enclave_name) < 0)
  {
    sbi_bug("M mode: asyn_enclave_call: transfer relay page is failed\n");
    goto failed;
  }
  
  return ret;

failed:
  sbi_bug("M MODE: asyn_enclave_call: failed\n");
  return ret;
}

/**
 * \brief Split relay page into two pieces:
 * it will update the relay page entry in the global link memory,
 * and add a new splitted entry. Also, it will update the enclave->mm_arg_paddr
 * and enclave->mm_arg_size. If the relay page owned by single enclave is upper
 * than RELAY_PAGE_NUM, an error will be reported.
 *
 * \param mem_addr_u The split memory address.
 * \param mem_size The split memory size.
 * \param split_addr_u Thesplit point in the memory region.
 */
uintptr_t split_mem_region(uintptr_t *regs, uintptr_t mem_addr_u, uintptr_t mem_size, uintptr_t split_addr_u)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL;
  uintptr_t mem_addr = 0, split_addr = 0;
  int eid = 0;
  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: split_mem_region: CPU not in the enclave mode\n");
    return -1UL;
  }

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  release_enclave_metadata_lock();

  if(!enclave)
  {
    ret = -1UL;
    goto failed;
  }
  if((split_addr_u < mem_addr_u) || (split_addr_u > (mem_addr_u + mem_size)))
  {
    sbi_bug("M mode: split_mem_region: split address is not in the relay page region, split_addr_u: %lx, mem_addr_u %lx, upper_bound_addre %lx\n", split_addr_u, mem_addr_u, (mem_addr_u + mem_size));
    ret = -1UL;
    goto failed;
  }
  mem_addr = (unsigned long)va_to_pa((uintptr_t*)(enclave->root_page_table), (char *)mem_addr_u);
  split_addr = (unsigned long)va_to_pa((uintptr_t*)(enclave->root_page_table), (char *)split_addr_u);
  int found_corres_entry = 0;
  for(int kk = 0; kk < RELAY_PAGE_NUM; kk++)
  {
    if ((enclave->mm_arg_paddr[kk] == mem_addr) && (enclave->mm_arg_size[kk] == mem_size))
    {
      unsigned long split_size = enclave->mm_arg_paddr[kk] + enclave->mm_arg_size[kk] - split_addr;
      int found_empty_entry = 0;
      //free the old relay page entry in the global link memory
      __free_relay_page_entry(enclave->mm_arg_paddr[kk], enclave->mm_arg_size[kk]);
      //adjust the relay page region for enclave metadata
      enclave->mm_arg_size[kk] = split_addr - enclave->mm_arg_paddr[kk];
      //add the adjusted relay page entry in the global link memory
      __alloc_relay_page_entry(enclave->enclave_name, enclave->mm_arg_paddr[kk], enclave->mm_arg_size[kk]);
      //find the empty relay page entry for this enclave 
      for(int jj = kk; jj < RELAY_PAGE_NUM; jj++)
      {
        if ((enclave->mm_arg_paddr[jj] == 0) && (enclave->mm_arg_size[jj] == 0))
        {
          //add the new splitted relay page entry in the enclave metadata
          enclave->mm_arg_paddr[jj] = split_addr;
          enclave->mm_arg_size[jj] = split_size;
          // sbi_printf("M mode: split_mem_region2: split addr %lx split size %lx \n", enclave->mm_arg_paddr[jj], enclave->mm_arg_size[jj]);
          __alloc_relay_page_entry(enclave->enclave_name, enclave->mm_arg_paddr[jj], enclave->mm_arg_size[jj]);
          found_empty_entry = 1;
          break;
        }
      }
      if (!found_empty_entry)
      {
        sbi_bug("M mode: split mem region: can not find the empty entry for splitted relay page \n");
        ret = -1UL;
        goto failed;
      }
      found_corres_entry = 1;
      break;
    }
  }
  if (!found_corres_entry)
  {
    sbi_bug("M mode: split mem region: can not find the correspongind relay page region\n");
    ret = -1UL;
    goto failed;
  }
  return ret;

failed:
  sbi_bug("M MODE: split_mem_region: failed\n");
  return ret;
}

int free_all_relay_page(unsigned long *mm_arg_paddr, unsigned long *mm_arg_size)
{
  int ret = 0;
  for(int kk = 0; kk < RELAY_PAGE_NUM; kk++)
  {
    if (mm_arg_paddr[kk])
    {
      ret = __free_secure_memory(mm_arg_paddr[kk], mm_arg_size[kk]);
      ret = __free_relay_page_entry(mm_arg_paddr[kk], mm_arg_size[kk]);
    }
  }
  return ret;
}