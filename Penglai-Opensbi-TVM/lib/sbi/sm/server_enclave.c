#include "sm/sm.h"
#include "sm/enclave.h"
#include "sm/enclave_vm.h"
#include "sm/enclave_mm.h"
#include "sm/server_enclave.h"
#include "sm/ipi.h"
#include "sm/attest.h"
#include "sbi/sbi_string.h"
#include "sbi/sbi_console.h"

struct link_mem_t* server_enclave_head = NULL;
struct link_mem_t* server_enclave_tail = NULL;

// Compare the server enclave name.
static int server_name_cmp(char* name1, char* name2)
{
  for(int i=0; i<NAME_LEN; ++i)
  {
    if(name1[i] != name2[i])
    {
      return 1;
    }
    if(name1[i] == 0)
    {
      return 0;
    }
  }
  return 0;
}

/**
 * \brief Allocate a server enclave with the given name from the server enclave list.
 *
 * \param server_name The given server enclave name.
 */
static struct server_enclave_t* __alloc_server_enclave(char *server_name)
{
  struct enclave_t* enclave = __alloc_enclave();
  if(!enclave)
    return NULL;

  struct link_mem_t *cur, *next;
  struct server_enclave_t* server_enclave = NULL;
  int found = 0;

  //server_enclave metadata list hasn't be initialized yet
  if(server_enclave_head == NULL)
  {
    server_enclave_head = init_mem_link(sizeof(struct server_enclave_t)*SERVERS_PER_METADATA_REGION, sizeof(struct server_enclave_t));
    if(!server_enclave_head)
    {
      goto failed;
    }
    server_enclave_tail = server_enclave_head;
  }

  //check whether server name already existed
  for(cur = server_enclave_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(int i = 0; i < (cur->slab_num); i++)
    {
      server_enclave = (struct server_enclave_t*)(cur->addr) + i;
      if(server_enclave->entity && server_name_cmp(server_name, server_enclave->server_name)==0)
      {
        sbi_bug("M mode: __alloc_server_enclave: server already existed!\n");
        server_enclave = (void*)(-1UL);
        goto failed;
      }
    }
  }

  found = 0;
  for(cur = server_enclave_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(int i = 0; i < (cur->slab_num); i++)
    {
      server_enclave = (struct server_enclave_t*)(cur->addr) + i;
      if(!(server_enclave->entity))
      {
        sbi_memcpy(server_enclave->server_name, server_name, NAME_LEN);
        server_enclave->entity = enclave;
        found = 1;
        break;
      }
    }
    if(found)
      break;
  }

  //don't have enough enclave metadata
  if(!found)
  {
    next = add_link_mem(&server_enclave_tail);
    if(next == NULL)
    {
      sbi_bug("M mode: __alloc_server_enclave: don't have enough mem\n");
      server_enclave = NULL;
      goto failed;
    }
    server_enclave = (struct server_enclave_t*)(next->addr);
    sbi_memcpy(server_enclave->server_name, server_name, NAME_LEN);
    server_enclave->entity = enclave;
  }

  return server_enclave;

failed:
  if(enclave)
    __free_enclave(enclave->eid);
  if(server_enclave == (void *)-1UL)
    return (void *)-1UL;
  if(server_enclave)
    sbi_memset((void*)server_enclave, 0, sizeof(struct server_enclave_t));

  return NULL;
}

/**
 * \brief Get the server enclav by eid.
 *
 * \param eid The server enclave id.
 */
static struct server_enclave_t* __get_server_enclave(int eid)
{
  struct link_mem_t *cur;
  struct server_enclave_t *server_enclave;
  int found;

  found = 0;
  for(cur = server_enclave_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(int i=0; i < (cur->slab_num); ++i)
    {
      server_enclave = (struct server_enclave_t*)(cur->addr) + i;
      if(server_enclave->entity && server_enclave->entity->eid == eid)
      {
        found = 1;
        break;
      }
    }
  }

  //haven't alloc this eid 
  if(!found)
  {
    sbi_bug("M mode: __get_server_enclave: haven't alloc this enclave:%d\r\n", eid);
    server_enclave = NULL;
  }

  return server_enclave;
}

/**
 * \brief Get the server enclave by the given name.
 *
 * \param server_name The given server enclave name.
 */
static struct server_enclave_t* __get_server_enclave_by_name(char* server_name)
{
  struct link_mem_t *cur;
  struct server_enclave_t *server_enclave;
  int i, found;

  found = 0;
  for(cur = server_enclave_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(i=0; i < (cur->slab_num); ++i)
    {
      server_enclave = (struct server_enclave_t*)(cur->addr) + i;
      if(server_enclave->entity && server_name_cmp(server_enclave->server_name, server_name)==0)
      {
        found = 1;
        break;
      }
    }
  }

  //haven't alloc this eid 
  if(!found)
  {
    sbi_bug("M mode: __get_server_enclave_by_name: haven't alloc this enclave:%s\n", server_name);
    server_enclave = NULL;
  }

  return server_enclave;
}

/**************************************************************/
/*                   called by host                           */
/**************************************************************/
/**
 * \brief Create the server enclave with the given create argument.
 *
 * \param create_args The create argument using in the creating server enclave phase.
 */
uintptr_t create_server_enclave(enclave_create_param_t create_args)
{
  struct enclave_t* enclave = NULL;
  struct server_enclave_t* server_enclave = NULL;
  uintptr_t ret = 0;
  int need_free_secure_memory = 0;

  acquire_enclave_metadata_lock();

  if(!enable_enclave())
  {
    ret = ENCLAVE_ERROR;
    goto failed;
  }
  if((create_args.paddr & (RISCV_PGSIZE-1)) || (create_args.size & (RISCV_PGSIZE-1)) || create_args.size < RISCV_PGSIZE)
  {
    ret = ENCLAVE_ERROR;
    goto failed;
  }

  //check enclave memory layout
  if(check_and_set_secure_memory(create_args.paddr, create_args.size) != 0)
  {
    ret = ENCLAVE_ERROR;
    goto failed;
  }
  need_free_secure_memory = 1;

  //check enclave memory layout
  if(check_enclave_layout(create_args.paddr + RISCV_PGSIZE, 0, -1UL, create_args.paddr, create_args.paddr + create_args.size) != 0)
  {
    ret = ENCLAVE_ERROR;
    goto failed;
  }

  server_enclave = __alloc_server_enclave(create_args.name);
  if(server_enclave == (void*)(-1UL))
  {
    ret = ENCLAVE_ERROR;
    goto failed;
  }
  if(!server_enclave)
  {
    ret = ENCLAVE_NO_MEM;
    goto failed;
  }

  enclave = server_enclave->entity;
  enclave->entry_point = create_args.entry_point;
  enclave->ocall_func_id = create_args.ecall_arg0;
  enclave->ocall_arg0 = create_args.ecall_arg1;
  enclave->ocall_arg1 = create_args.ecall_arg2;
  enclave->ocall_syscall_num = create_args.ecall_arg3;
  //enclave->retval = create_args.retval;
  enclave->host_ptbr = csr_read(CSR_SATP);
  enclave->root_page_table = create_args.paddr + RISCV_PGSIZE;
  enclave->thread_context.encl_ptbr = ((create_args.paddr+RISCV_PGSIZE) >> RISCV_PGSHIFT) | SATP_MODE_CHOICE;
  enclave->type = SERVER_ENCLAVE;
  //we directly set server_enclave's state as RUNNABLE as it won't be called by run_enclave call
  enclave->state = RUNNABLE;
  enclave->caller_eid = -1;
  enclave->top_caller_eid = -1;
  enclave->cur_callee_eid = -1;
  enclave->ocalling_shm_key = -1UL;
  //traverse vmas
  struct pm_area_struct* pma = (struct pm_area_struct*)(create_args.paddr);
  struct vm_area_struct* vma = (struct vm_area_struct*)(create_args.paddr + sizeof(struct pm_area_struct));
  pma->paddr = create_args.paddr;
  pma->size = create_args.size;
  pma->free_mem = create_args.free_mem;
  pma->pm_next = NULL;
  enclave->pma_list = pma;
  traverse_vmas(enclave->root_page_table, vma);

  //FIXME: here we assume there are exactly text(include text/data/bss) vma and stack vma
  while(vma)
  {
    if(vma->va_start == ENCLAVE_DEFAULT_TEXT_BASE)
    {
      enclave->text_vma = vma;
    }
    if(vma->va_end == ENCLAVE_DEFAULT_STACK_BASE)
    {
      enclave->stack_vma = vma;
      enclave->_stack_top = enclave->stack_vma->va_start;
    }
    vma->pma = pma;
    vma = vma->vm_next;
  }
  if(enclave->text_vma)
    enclave->text_vma->vm_next = NULL;
  if(enclave->stack_vma)
    enclave->stack_vma->vm_next = NULL;
  enclave->_heap_top = ENCLAVE_DEFAULT_HEAP_BASE;
  enclave->heap_vma = NULL;
  enclave->mmap_vma = NULL;

  enclave->free_pages = NULL;
  enclave->free_pages_num = 0;
  uintptr_t free_mem = create_args.paddr + create_args.size - RISCV_PGSIZE;
  while(free_mem >= create_args.free_mem)
  {
    struct page_t *page = (struct page_t*)free_mem;
    page->paddr = free_mem;
    page->next = enclave->free_pages;
    enclave->free_pages = page;
    enclave->free_pages_num += 1;
    free_mem -= RISCV_PGSIZE;
  }
  // check shm
    if(create_args.shm_paddr && create_args.shm_size &&
      !(create_args.shm_paddr & (RISCV_PGSIZE-1)) && !(create_args.shm_size & (RISCV_PGSIZE-1)))
  {
    mmap((uintptr_t*)(enclave->root_page_table), &(enclave->free_pages), ENCLAVE_DEFAULT_SHM_BASE, create_args.shm_paddr, create_args.shm_size);
    enclave->shm_paddr = create_args.shm_paddr;
    enclave->shm_size = create_args.shm_size;
  }
  else
  {
    enclave->shm_paddr = 0;
    enclave->shm_size = 0;
  }

  hash_enclave(enclave, (void*)(enclave->hash), 0);
  copy_word_to_host((unsigned int*)create_args.eid_ptr, enclave->eid);
  release_enclave_metadata_lock();
  return ret;

failed:
  if(need_free_secure_memory)
  {
    free_secure_memory(create_args.paddr, create_args.size);
  }
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief Destroy the server enclave if server enclave is not runnable.
 *
 * \param regs The host regs.
 * \param eid The server enclave id.
 */
uintptr_t destroy_server_enclave(uintptr_t* regs, unsigned int eid)
{
  uintptr_t retval = 0;
  struct enclave_t *enclave = NULL;
  struct server_enclave_t *server_enclave = NULL;
  struct pm_area_struct* pma = NULL;
  int need_free_enclave_memory = 0;

  acquire_enclave_metadata_lock();

  server_enclave = __get_server_enclave(eid);
  if(!server_enclave)
  {
    sbi_bug("M mode: destroy_server_enclave: server%d is not found\r\n", eid);
    retval = -1UL;
    goto out;
  }
  enclave = server_enclave->entity;
  if(!enclave || enclave->state < FRESH)
  {
    sbi_bug("M mode: destroy_server_enclave: server%d can not be accessed\r\n", eid);
    retval = -1UL;
    goto out;
  }

  sbi_memset((void*)server_enclave, 0, sizeof(struct server_enclave_t));

  if(enclave->state != RUNNING)
  {
    pma = enclave->pma_list;
    need_free_enclave_memory = 1;
    __free_enclave(eid);
  }
  else
  {
    //TODO: use ipi to stop the server enclave
    sbi_bug("M mode: destroy_server_enclave: server enclave is running, can not destroy\n");
  }

out:
  release_enclave_metadata_lock();
  if(need_free_enclave_memory)
  {
    free_enclave_memory(pma);
  }

  return retval;
}
/**************************************************************/
/*                   called by enclave                        */
/**************************************************************/
/**
 * \brief Acquire the server enclave and retrieve the corresponding server enclave handler.
 *
 * \param server_name_u The acquired server enclave name.
 */
uintptr_t acquire_server_enclave(char* server_name_u)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL;
  struct server_enclave_t *server_enclave = NULL;
  char *server_name = NULL;
  int eid = 0;
  if(check_in_enclave_world() < 0)
  {
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if(!enclave)
  {
    ret = -1UL;
    goto failed;
  }

  server_name = va_to_pa((uintptr_t*)(enclave->root_page_table), server_name_u);
  if(!server_name)
  {
    ret = -1UL;
    goto failed;
  }
  server_enclave = __get_server_enclave_by_name(server_name);
  if(!server_enclave)
  {
    ret = -1UL;
    goto failed;
  }
  ret = server_enclave->entity->eid;

  release_enclave_metadata_lock();
  return ret;

failed:
  release_enclave_metadata_lock();
  sbi_bug("M MODE: acquire_server_enclave: acquire encalve failed\n");
  return ret;
}

/**
 * \brief Get the attestation report of local enclave with the given enclave name.
 *
 * \param name The attested enclave name
 * \param report The attestation report address in the caller enclave.
 * \param nonce The attestation nonce
 */
uintptr_t get_server_enclave_attest_report(char* name, uintptr_t *report, uintptr_t nonce)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL;
  struct enclave_t *attest_enclave = NULL;
  int eid = 0, attest_eid = 0; 
  attest_eid = acquire_server_enclave(name);
  if (attest_eid == -1UL)
  {
    sbi_bug("M mode: get_server_enclave_attest_report: server enclave is not existed\n");
    return -1UL;
  }
  attest_enclave = __get_enclave(attest_eid);

  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: get_enclave_attest_report: CPU is not in the enclave mode\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if(!enclave || enclave->state != RUNNING)
  {
    ret = -1UL;
    sbi_bug("M mode: get_enclave_attest_report: enclave%d can not be accessed!\n", eid);
    goto out;
  }

  // Get the physical address of the attestaion report
  struct report_t m_report;
  struct report_t* u_report = va_to_pa((uintptr_t*)(enclave->root_page_table), (void*)report);
  if(!u_report)
  {
    sbi_bug("M mode: get_enclave_attest_report: report is not existed \n");
    ret = -1UL;
    goto out;
  }
  
  sbi_memcpy((void*)(m_report.dev_pub_key), (void*)DEV_PUB_KEY, PUBLIC_KEY_SIZE);
  sbi_memcpy((void*)(m_report.sm.hash), (void*)SM_HASH, HASH_SIZE);
  sbi_memcpy((void*)(m_report.sm.sm_pub_key), (void*)SM_PUB_KEY, PUBLIC_KEY_SIZE);
  sbi_memcpy((void*)(m_report.sm.signature), (void*)SM_SIGNATURE, SIGNATURE_SIZE);

  update_enclave_hash((char*)(m_report.enclave.hash), (void*)(attest_enclave->hash), nonce);
  sign_enclave((void*)(m_report.enclave.signature), (void*)(m_report.enclave.hash));
  m_report.enclave.nonce = nonce;

  // Copy attestation report to enclave
  sbi_memcpy(u_report, &m_report, sizeof(struct report_t));
out:
  release_enclave_metadata_lock();
  return ret;
}

/* Retrive the eid of the caller enclave  */
/**
 * \brief Get the caller enclave id.
 */
uintptr_t get_caller_id(uintptr_t* regs)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL;
  int eid = 0; 
  if(check_in_enclave_world() < 0)
  {
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if(!enclave)
  {
    ret = -1UL;
    goto failed;
  }

  sbi_memcmp(&ret, enclave->hash, HASH_SIZE);

  release_enclave_metadata_lock();
  return ret;

failed:
  release_enclave_metadata_lock();
  sbi_bug("M MODE: get_caller_id: failed\n");
  return ret;
}
