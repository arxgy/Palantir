#include "sbi/riscv_encoding.h"
#include "sbi/sbi_math.h"
#include "sbi/riscv_locks.h"
#include "sbi/sbi_bitops.h" 
#include "sbi/sbi_ipi_destroy_enclave.h"
#include "sbi/sbi_ipi_stop_enclave.h"
#include "sbi/sbi_console.h"
#include "sm/enclave.h"
#include "sm/server_enclave.h"
#include "sm/enclave_vm.h"
#include "sm/enclave_mm.h"
#include "sm/sm.h"
#include "sm/platform/pt_area/platform_thread.h"
#include "sm/ipi.h"
#include "sm/attest.h"
#include "sm/key.h"
#include <sbi/sbi_tlb.h>
#include <sm/enclave_error.h>

int eapp_args = 0;
extern int CPU_IN_CRITICAL;
extern int CPU_NEED_FLUSH[MAX_HARTS];
extern int CPU_FLUSH_TAG;
extern bool NEED_DESTORY_ENCLAVE[MAX_HARTS];
extern bool NEED_STOP_ENCLAVE[MAX_HARTS];

extern spinlock_t cpu_in_critical_lock;
#define SET_FLUSH_TAG(hartid) CPU_FLUSH_TAG|(hartid)
#define REMOVE_FLUSH_TAG(hartid) CPU_FLUSH_TAG&(~(1<<hartid)) 

static struct cpu_state_t cpus[MAX_HARTS] = {{0,}, };

//whether cpu is in enclave-mode
int cpu_in_enclave(int i)
{
  return cpus[i].in_enclave;
}

//the eid of current cpu (if it is in enclave mode)
int cpu_eid(int i)
{
  return cpus[i].eid;
}

//spinlock
static spinlock_t enclave_metadata_lock = SPINLOCK_INIT;
inline void acquire_enclave_metadata_lock()
{
  spin_lock(&enclave_metadata_lock);
}
inline void release_enclave_metadata_lock()
{
  spin_unlock(&enclave_metadata_lock);
}

static spinlock_t enclave_relay_page_lock = SPINLOCK_INIT;

//enclave metadata
struct link_mem_t* enclave_metadata_head = NULL;
struct link_mem_t* enclave_metadata_tail = NULL;

struct link_mem_t* shadow_enclave_metadata_head = NULL;
struct link_mem_t* shadow_enclave_metadata_tail = NULL;

struct link_mem_t* relay_page_head = NULL;
struct link_mem_t* relay_page_tail = NULL;

/**
 * \brief Compare the enclave name.
 * 
 * \param name1 The given enclave name1. 
 * \param name2 The given enclave name2. 
 */
static int enclave_name_cmp(char* name1, char* name2)
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

//copy data from host
uintptr_t copy_from_host(void* dest, void* src, size_t size)
{
  //FIXME: check whether src is a legitimate address
  if(test_public_range(PADDR_TO_PFN((unsigned long)src), 1) != 0)
  {
    sbi_bug("M mode: copy_from_host: illegal copy from host \n");
    return -1;
  }
  sbi_memcpy(dest, src, size);
  return 0;
}

// copy data to host
uintptr_t copy_to_host(void* dest, void* src, size_t size)
{
  //FIXME: check whether dest is a legitimate address
  if(test_public_range(PADDR_TO_PFN((unsigned long)dest), 1) != 0)
  {
    sbi_bug("M mode: copy_to_host: illegal copy to host \n");
    return -1;
  }
  sbi_memcpy(dest, src, size);
  return 0;
}

// Copy a word value to the host 
int copy_word_to_host(unsigned int* ptr, uintptr_t value)
{
  //FIXME: check whether ptr is a legitimate address
  if(test_public_range(PADDR_TO_PFN((unsigned long)ptr), 1) != 0)
  {
    sbi_bug("M mode: copy_word_to_host: illegal copy to host \n");
    return -1;
  }
  *ptr = value;
  return 0;
}

// Copy double word to the host
int copy_dword_to_host(uintptr_t* ptr, uintptr_t value)
{
  //FIXME: check whether ptr is a legitimate address
  if(test_public_range(PADDR_TO_PFN((unsigned long)ptr), 1) != 0)
  {
    sbi_bug("M mode: copy_dword_to_host: illegal copy to host \n");
    return -1;
  }
  *ptr = value;
  return 0;
}

// Should only be called after acquire enclave_metadata_lock
static void enter_enclave_world(int eid)
{
  cpus[csr_read(CSR_MHARTID)].in_enclave = ENCLAVE_MODE;
  cpus[csr_read(CSR_MHARTID)].eid = eid;

  platform_enter_enclave_world();
}

// Get the current enclave id
int get_curr_enclave_id()
{
  return cpus[csr_read(CSR_MHARTID)].eid;
}

// Should only be called after acquire enclave_metadata_lock
static void exit_enclave_world()
{
  cpus[csr_read(CSR_MHARTID)].in_enclave = NORMAL_MODE;
  cpus[csr_read(CSR_MHARTID)].eid = -1;

  platform_exit_enclave_world();
}

// check whether we are in enclave-world through in_enclave state
int check_in_enclave_world()
{
  if(!(cpus[csr_read(CSR_MHARTID)].in_enclave))
    return -1;

  if(platform_check_in_enclave_world() < 0)
    return -1;

  return 0;
}

// Invoke the platform-specific authentication
int check_enclave_authentication()
{
  if(platform_check_enclave_authentication() != 0)
    return -1;

  return 0;
}

// Wrapper of the platform-specific switch func
static void switch_to_enclave_ptbr(struct thread_state_t* thread, uintptr_t ptbr)
{
  platform_switch_to_enclave_ptbr(thread, ptbr);
}

// Wrapper of the platform-specific switch func
static void switch_to_host_ptbr(struct thread_state_t* thread, uintptr_t ptbr)
{
  platform_switch_to_host_ptbr(thread, ptbr);
}

/**
 * \brief It creates a new link memory range with the given memory size. Each 
 * 	entry is slab_size large.
 * 
 * \param mem_size Init link memory size.
 * \param slab_size The slab size for the link memmory 
 */
struct link_mem_t* init_mem_link(unsigned long mem_size, unsigned long slab_size)
{
  struct link_mem_t* head;
  unsigned long resp_size = 0;
  head = (struct link_mem_t*)mm_alloc(mem_size, &resp_size);

  if(head == NULL) {
    return NULL;
  }
  else
    sbi_memset((void*)head, 0, resp_size);

  if(resp_size <= sizeof(struct link_mem_t) + slab_size)
  {
    mm_free(head, resp_size);
    sbi_bug("M mode: init_mem_link: The monitor has not reserved enough secure memory\n");
    return NULL;
  }

  head->mem_size = resp_size;
  head->slab_size = slab_size;
  head->slab_num = (resp_size - sizeof(struct link_mem_t)) / slab_size;
  void* align_addr = (char*)head + sizeof(struct link_mem_t);
  head->addr = (char*)size_up_align((unsigned long)align_addr, slab_size);
  head->next_link_mem = NULL;

  return head;
}

/**
 * \brief Create a new link memory range and append it into tail of the corresponding link memory list.
 * 
 * \param tail Return value, The tail of the link memory.
 */
struct link_mem_t* add_link_mem(struct link_mem_t** tail)
{
  struct link_mem_t* new_link_mem;
  unsigned long resp_size = 0;

  new_link_mem = (struct link_mem_t*)mm_alloc((*tail)->mem_size, &resp_size);

  if (new_link_mem == NULL) {
    sbi_printf("[sm] oh, mm_alloc failed!\n");
    return NULL;
  }
  else
    sbi_memset((void*)new_link_mem, 0, resp_size);

  if(resp_size <= sizeof(struct link_mem_t) + (*tail)->slab_size)
  {
    mm_free(new_link_mem, resp_size);
  }

  (*tail)->next_link_mem = new_link_mem;
  new_link_mem->mem_size = resp_size;
  new_link_mem->slab_num = (resp_size - sizeof(struct link_mem_t)) / (*tail)->slab_size;
  new_link_mem->slab_size = (*tail)->slab_size;
  void* align_addr = (char*)new_link_mem + sizeof(struct link_mem_t);
  new_link_mem->addr = (char*)size_up_align((unsigned long)align_addr, (*tail)->slab_size);
  new_link_mem->next_link_mem = NULL;
  
  *tail = new_link_mem;

  return new_link_mem;
}

/**
 * \brief Remove the entry (indicated by ptr) from the head's list.
 * \param head Head of the link memory.
 * \param pte The removed link memory ptr.
 */
int remove_link_mem(struct link_mem_t** head, struct link_mem_t* ptr)
{
  struct link_mem_t *cur_link_mem, *tmp_link_mem;
  int retval =0;

  cur_link_mem = *head;
  if (cur_link_mem == ptr)
  {
    *head = cur_link_mem->next_link_mem;
    mm_free(cur_link_mem, cur_link_mem->mem_size);
    return retval;
  }

  for(; cur_link_mem != NULL; cur_link_mem = cur_link_mem->next_link_mem)
  {
    if (cur_link_mem->next_link_mem == ptr)
    {
      tmp_link_mem = cur_link_mem->next_link_mem;
      cur_link_mem->next_link_mem = cur_link_mem->next_link_mem->next_link_mem;
      mm_free(tmp_link_mem, tmp_link_mem->mem_size);
      return retval;
    }
  }

  return retval;
}

/** 
 * \brief alloc an enclave_t structure from encalve_metadata_head.
 * Eid represents the location in the enclave metadata list.
 */
struct enclave_t* __alloc_enclave()
{
  struct link_mem_t *cur, *next;
  struct enclave_t* enclave = NULL;
  int i = 0, found = 0, eid = 0;

  //enclave metadata list hasn't be initialized yet
  if(enclave_metadata_head == NULL)
  {
    enclave_metadata_head = init_mem_link(ENCLAVE_METADATA_REGION_SIZE, sizeof(struct enclave_t));
    if(!enclave_metadata_head)
    {
      //commented by luxu
      //sbi_printf("M mode: __alloc_enclave: don't have enough mempry\n");
      goto alloc_eid_out;
    }
    enclave_metadata_tail = enclave_metadata_head;
  }

  // sbi_printf("__alloc_enclave: head[0x%p]; tail[0x%p]\n", enclave_metadata_head, enclave_metadata_tail);
  // for(cur = enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
  // {
  //   sbi_printf("==>: pointer [0x%p]\n", cur);
  // }

  for(cur = enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(i = 0; i < (cur->slab_num); i++)
    {
      enclave = (struct enclave_t*)(cur->addr) + i;
      if(enclave->state == INVALID)
      {
        sbi_memset((void*)enclave, 0, sizeof(struct enclave_t));
        enclave->state = FRESH;
        enclave->eid = eid;
        found = 1;
        break;
      }
      eid++;
    }
    if(found)
      break;
  }

  //don't have enough enclave metadata
  if(!found)
  {
    sbi_printf("[sm] we don't have enough enclave metadata\n");
    next = add_link_mem(&enclave_metadata_tail);
    if(next == NULL)
    {
      sbi_bug("M mode: __alloc_enclave: add new link memory is failed\n");
      enclave = NULL;
      goto alloc_eid_out;
    }
    enclave = (struct enclave_t*)(next->addr);
    sbi_memset((void*)enclave, 0, sizeof(struct enclave_t));
    enclave->state = FRESH;  
    enclave->eid = eid;
  }

alloc_eid_out:
  return enclave;
}
 
/** 
 * \brief Free the enclave metadata with the given eid.
 * 
 * \param eid enclave id, which indicates the location in enclave metadata list.
 */
int __free_enclave(int eid)
{
  struct link_mem_t *cur;
  struct enclave_t *enclave = NULL;
  int found=0 , count=0, ret_val=0;

  for(cur = enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
  {
    if(eid < (count + cur->slab_num))
    {
      enclave = (struct enclave_t*)(cur->addr) + (eid - count);
      sbi_memset((void*)enclave, 0, sizeof(struct enclave_t));
      enclave->state = INVALID;
      found = 1;
      ret_val = 0;
      break;
    }
    count += cur->slab_num;
  }

  //haven't alloc this eid 
  if(!found)
  {
    sbi_bug("M mode: __free_enclave: haven't alloc this eid\n");
    ret_val = -1;
  }

  return ret_val;
}

/** 
 * \brief Get the enclave metadata with the given eid.
 * 
 * \param eid enclave id, which indicates the location in enclave metadata list.
 */
struct enclave_t* __get_enclave(int eid)
{
  struct link_mem_t *cur;
  struct enclave_t *enclave;
  int found=0, count=0;

  for(cur = enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
  {
    if(eid < (count + cur->slab_num))
    {
      enclave = (struct enclave_t*)(cur->addr) + (eid - count);
      found = 1;
      break;
    }

    count += cur->slab_num;
  }

  //haven't alloc this eid 
  if(!found)
  {
    sbi_bug("M mode: __get_enclave: haven't alloc this enclave\n");
    enclave = NULL;
  }

  return enclave;
}

/** 
 * \brief Check whether the enclave name is duplicated
 * return 0 if the enclave name is unique, otherwise
 * return -1.
 * 
 * \param enclave_name Checked enclave name.
 * \param target_eid The target enclave id
 */
int check_enclave_name(char *enclave_name, int target_eid)
{
  struct link_mem_t *cur;
  struct enclave_t* enclave = NULL;
  int i=0, eid=0;
  for(cur = enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(i = 0; i < (cur->slab_num); i++)
    {
      enclave = (struct enclave_t*)(cur->addr) + i;
      if((enclave->state > INVALID) &&(enclave_name_cmp(enclave_name, enclave->enclave_name)==0) && (target_eid != eid))
      {
        sbi_bug("M mode: check enclave name: enclave name is already existed, matched enclave name is %s and target enclave name is %s\n", enclave->enclave_name, enclave_name);
        sbi_bug("M mode: target eid %d eid %d state %d\n", target_eid, eid, enclave->state);
        return -1;
      }
      eid++;
    }
  }
  return 0;
}

/** 
 * \brief Alloc shadow enclave metadata in the shadow enclave list.
 */
static struct shadow_enclave_t* __alloc_shadow_enclave()
{
  struct link_mem_t *cur, *next;
  struct shadow_enclave_t* shadow_enclave = NULL;
  int i=0, found=0, eid=0;

  //enclave metadata list hasn't be initialized yet
  if(shadow_enclave_metadata_head == NULL)
  {
    shadow_enclave_metadata_head = init_mem_link(SHADOW_ENCLAVE_METADATA_REGION_SIZE, sizeof(struct shadow_enclave_t));
    if(!shadow_enclave_metadata_head)
    {
      //commented by luxu
      //sbi_printf("M mode: __alloc_enclave: don't have enough memory\n");
      goto alloc_eid_out;
    }
    shadow_enclave_metadata_tail = shadow_enclave_metadata_head;
  }

  for(cur = shadow_enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(i = 0; i < (cur->slab_num); i++)
    {
      shadow_enclave = (struct shadow_enclave_t*)(cur->addr) + i;
      if(shadow_enclave->state == INVALID)
      {
        sbi_memset((void*)shadow_enclave, 0, sizeof(struct shadow_enclave_t));
        shadow_enclave->state = FRESH;
        shadow_enclave->eid = eid;
        found = 1;
        break;
      }
      eid++;
    }
    if(found)
      break;
  }

  // don't have enough enclave metadata
  if(!found)
  {
    next = add_link_mem(&shadow_enclave_metadata_tail);
    if(next == NULL)
    {
      sbi_printf("M mode: __alloc_shadow_enclave: don't have enough mem\n");
      shadow_enclave = NULL;
      goto alloc_eid_out;
    }
    shadow_enclave = (struct shadow_enclave_t*)(next->addr);
    sbi_memset((void*)shadow_enclave, 0, sizeof(struct shadow_enclave_t));
    shadow_enclave->state = FRESH;  
    shadow_enclave->eid = eid;
  }

alloc_eid_out:
  return shadow_enclave;
}

/** 
 * \brief Get the shadow enclave metadata with the given shadow eid.
 * 
 * \param eid the shadow enclave id.
 */
static struct shadow_enclave_t* __get_shadow_enclave(int eid)
{
  struct link_mem_t *cur;
  struct shadow_enclave_t *shadow_enclave;
  int found=0, count=0;

  for(cur = shadow_enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
  {
    if(eid < (count + cur->slab_num))
    {
      shadow_enclave = (struct shadow_enclave_t*)(cur->addr) + (eid - count);
      found = 1;
      break;
    }

    count += cur->slab_num;
  }

  //haven't alloc this eid 
  if(!found)
  {
    sbi_bug("M mode: __get_enclave: haven't alloc this shadow_enclave\n");
    shadow_enclave = NULL;
  }

  return shadow_enclave;
}

/** 
 * \brief Free the shadow enclave with the given eid in the shadow enclave list.
 * 
 * \param eid shadow enclave id, which represents the location in the shadow enclave list.
 */
int __free_shadow_enclave(int eid)
{
  struct link_mem_t *cur;
  struct shadow_enclave_t *shadow_enclave = NULL;
  int found=0 , count=0, ret_val=0;

  for(cur = shadow_enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
  {
    if(eid < (count + cur->slab_num))
    {
      shadow_enclave = (struct shadow_enclave_t*)(cur->addr) + (eid - count);
      sbi_memset((void*)shadow_enclave, 0, sizeof(struct shadow_enclave_t));
      shadow_enclave->state = INVALID;
      found = 1;
      ret_val = 0;
      break;
    }
    count += cur->slab_num;
  }

  //haven't alloc this eid 
  if(!found)
  {
    sbi_bug("M mode: __free_shadow_enclave_enclave: haven't alloc this eid\n");
    ret_val = -1;
  }

  return ret_val;
}

/**
 * \brief This function is used to handle IPC in enclave,
 * 	  it will return the last enclave in the chain.
 * 	  This is used to help us identify the real executing encalve.
 * 
 * \param eid The enclave id.
 */
struct enclave_t* __get_real_enclave(int eid)
{
  struct enclave_t* enclave = __get_enclave(eid);
  if(!enclave)
    return NULL;

  struct enclave_t* real_enclave = NULL;
  if(enclave->cur_callee_eid == -1)
    real_enclave = enclave;
  else
    real_enclave = __get_enclave(enclave->cur_callee_eid);

  return real_enclave;
}

/********************************************/
/*            Enclave Ownership             */
/********************************************/
/*
  provided by Anonymous Author @ May 10, 2023.
 */

/** 
 * \brief allocate children enclave entry unconditionally.
 * 
 * \param metadata_head Parent enclave's children link head
 * \param metadata_tail Parent enclave's children link tail
 */
struct children_enclave_t* __alloc_children(struct link_mem_t *metadata_head, struct link_mem_t *metadata_tail, uintptr_t *ptr)
{
  struct link_mem_t *cur, *next;
  struct children_enclave_t* enclave = NULL;
  int i = 0, found = 0;

  // struct link_mem_t *metadata_head = *metadata_head_ptr;
  // struct link_mem_t *metadata_tail = *metadata_tail_ptr;
  
  if (metadata_head == NULL)
  {
    metadata_head = init_mem_link(CHILDREN_METADATA_REGION_SIZE, sizeof(struct children_enclave_t));
    if(!metadata_head)
    {
      // sbi_printf("M mode: __alloc_children: don't have enough mempry\n");
      goto alloc_children_out;
    }
    metadata_tail = metadata_head;
  }
  for (cur = metadata_head; cur != NULL; cur = cur->next_link_mem)
  {
    for (i = 0; i < (cur->slab_num); i++)
    {
      enclave = (struct children_enclave_t*)(cur->addr) + i;
      if (enclave->state == INVALID)
      {
        sbi_memset((void*)enclave, 0, sizeof(struct children_enclave_t));
        enclave->state = FRESH;
        found = 1;
        break;
      }
    }
    if (found)
      break;
  }
  if (!found)
  {
    sbi_printf("[sm] we don't have enough enclave metadata\n");
    next = add_link_mem(&metadata_tail);
    if(next == NULL)
    {
      sbi_bug("M mode: __alloc_enclave: add new link memory is failed\n");
      enclave = NULL;
      goto alloc_children_out;
    }
    enclave = (struct children_enclave_t*)(next->addr);
    sbi_memset((void*)enclave, 0, sizeof(struct children_enclave_t));
    enclave->state = FRESH;  
  }
  *ptr = (uintptr_t)metadata_head;
  /* if return NULL, higher layer function must return ENCLAVE_NO_MEM */
alloc_children_out: 
  return enclave;
}

/** 
 * \brief free children enclave entry unconditionally.
 * 
 * \param eid Target children enclave eid
 * \param metadata_head Parent enclave's children link head
 * 
 * \details We need to add duplication check in future. 
 *          But now we trust the sanity check of existing eid slab struct in Penglai.
 */
int __free_children(int eid, struct link_mem_t *metadata_head)
{
  struct link_mem_t *cur;
  struct children_enclave_t *enclave;
  int i = 0, found = 0, retval = 0;

  for (cur = metadata_head; cur != NULL; cur = cur->next_link_mem)
  {
    for (i = 0; i < (cur->slab_num); i++)
    {
      enclave = (struct children_enclave_t*)(cur->addr) + i;
      if (enclave->state == FRESH && enclave->eid == eid) 
      {
        sbi_memset((void *)enclave, 0, sizeof(struct children_enclave_t));
        enclave->state = INVALID;
        found = 1;
        retval = 0;
        break;
      }
    }
    if (found)
      break;
  }

  //haven't alloc this eid 
  if(!found) 
  {
    sbi_bug("M mode: __free_children: haven't alloc this children eid\n");
    retval = -1;
  }
  return retval;
}

/** 
 * \brief get children enclave entry unconditionally.
 * 
 * \param eid Target children enclave eid
 * \param metadata_head Parent enclave's children link head
 * 
 * \details return NULL means eid not found. But unlike __free_children, it will not report sbi_bug.
 */
struct children_enclave_t* __get_children(int eid, struct link_mem_t *metadata_head)
{
  struct link_mem_t *cur;
  struct children_enclave_t *enclave;
  int i = 0, found = 0;

  for (cur = metadata_head; cur != NULL; cur = cur->next_link_mem)
  {

    for (i = 0; i < (cur->slab_num); i++)
    {
      enclave = (struct children_enclave_t*)(cur->addr) + i;

      if (enclave->state == FRESH && enclave->eid == eid) {
        found = 1;
        break;
      }
    }
    if (found)
      break;
  }

  //haven't alloc this eid 
  if(!found)
    enclave = NULL;

  return enclave;
}

/********************************************/
/*                   Relay Page             */
/********************************************/

/*
  allocate a new entry in the link memory, if link head is NULL, we initialize the link memory.
  When the ownership of  relay page is changed, we need first destroy the old relay page entry which
  records the out of  data ownership of relay page, and then allocate the new relay page entry with
  new ownership.

  Return value:
  relay_pagfe_entry @ allocate the relay page successfully
  NULL @ allcate the relay page is failed
 */

/**
 * \brief Alloc a relay page entry in the relay page list.
 * 
 * \param enclave_name The enclave name (specified by the user).
 * \param relay_page_addr The relay page address for the given enclave (enclave_name).
 * \param relay_page_size The relay page size for the given enclave (enclave_name).
 */
struct relay_page_entry_t* __alloc_relay_page_entry(char *enclave_name, unsigned long relay_page_addr, unsigned long relay_page_size)
{
  struct link_mem_t *cur, *next;
  struct relay_page_entry_t* relay_page_entry = NULL;
  int found = 0, link_mem_index = 0;

  spin_lock(&enclave_relay_page_lock);
  //relay_page_entry metadata list hasn't be initialized yet
  if(relay_page_head == NULL)
  {
    relay_page_head = init_mem_link(sizeof(struct relay_page_entry_t)*ENTRY_PER_RELAY_PAGE_REGION, sizeof(struct relay_page_entry_t));
    
    if(!relay_page_head)
      goto failed;
    
    relay_page_tail = relay_page_head;
  }

  //check whether relay page is owned by another enclave
  for(cur = relay_page_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(int i = 0; i < (cur->slab_num); i++)
    {
      relay_page_entry = (struct relay_page_entry_t*)(cur->addr) + i;
      if(relay_page_entry->addr == relay_page_addr)
      {
        sbi_bug("M mode: __alloc_relay_page_entry: the relay page is owned by another enclave\n");
        relay_page_entry = (void*)(-1UL);
        goto failed;
      }
    }
  }
  //traverse the link memory and check whether there is an empty entry in the link memoy
  for(cur = relay_page_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(int i = 0; i < (cur->slab_num); i++)
    {
      relay_page_entry = (struct relay_page_entry_t*)(cur->addr) + i;
      //address in the relay page entry remains zero which means the entry is not used
      if(relay_page_entry->addr == 0)
      {
        sbi_memcpy(relay_page_entry->enclave_name, enclave_name, NAME_LEN);
        relay_page_entry->addr = relay_page_addr;
        relay_page_entry->size = relay_page_size;
        found = 1;
        break;
      }
    }
    if(found)
      break;
    link_mem_index = link_mem_index + 1; 
  }

  //don't have enough memory to allocate a new entry in current link memory, so allocate a new link memory 
  if(!found)
  {
    next = add_link_mem(&relay_page_tail);
    if(next == NULL)
    {
      sbi_bug("M mode: __alloc_relay_page_entry: don't have enough mem\n");
      relay_page_entry = NULL;
      goto failed;
    }
    relay_page_entry = (struct relay_page_entry_t*)(next->addr);
    sbi_memcpy(relay_page_entry->enclave_name, enclave_name, NAME_LEN);
    relay_page_entry->addr = relay_page_addr;
    relay_page_entry->size = relay_page_size;
  }


  spin_unlock(&enclave_relay_page_lock);
  return relay_page_entry;

failed:
  if(relay_page_entry)
    sbi_memset((void*)relay_page_entry, 0, sizeof(struct relay_page_entry_t));


  spin_unlock(&enclave_relay_page_lock);
  return NULL;
}

/**
 * \brief Free the relay page indexed by the the given enclave name.
 * now we just set the address in the relay page entry to zero
 * which means this relay page entry is not used.
 * 
 * return value:
 * 0 : free the relay_page successfully
 * -1 : can not find the corresponding relay page
 * 
 * \param relay_page_addr The relay page address.
 * \param relay_page_size The relay page size.
 */
int __free_relay_page_entry(unsigned long relay_page_addr, unsigned long relay_page_size)
{
  struct link_mem_t *cur;
  struct relay_page_entry_t *relay_page_entry = NULL;
  int found = 0, ret_val = 0;

  spin_lock(&enclave_relay_page_lock);
  // sbi_printf("free relay page address %lx relay_page_size %lx\n", relay_page_addr, relay_page_size);
  for(cur = relay_page_head; cur != NULL; cur = cur->next_link_mem)
  {
    for(int i = 0; i < (cur->slab_num); i++)
    {
      relay_page_entry = (struct relay_page_entry_t*)(cur->addr) + i;
      //find the corresponding relay page entry by given address and size
      if((relay_page_entry->addr >= relay_page_addr) && ((relay_page_entry->addr + relay_page_entry->size) <= (relay_page_addr + relay_page_size)))
      {
        found = 1;
        sbi_memset(relay_page_entry->enclave_name, 0, NAME_LEN);
        relay_page_entry->addr = 0;
        relay_page_entry->size = 0;
      }
    }
  }
  //haven't alloc this relay page
  if(!found)
  {
    sbi_bug("M mode: __free_relay_page_entry: relay page  [%lx : %lx + %lx]is not existed \n", relay_page_addr, relay_page_addr, relay_page_size);
    ret_val = -1;
  }

  spin_unlock(&enclave_relay_page_lock);
  return ret_val;
}

/**
 * \brief Retrieve the relay page entry with the given enclave name.
 * 
 * \param enclave_name: Get the relay page entry with given enclave name.
 * \param slab_index: Find the corresponding relay page entry and return the slab index in the link memory.
 * \param link_mem_index: Find the corresponding relay page entry and return the link mem index.
 */
struct relay_page_entry_t* __get_relay_page_by_name(char* enclave_name, int *slab_index, int *link_mem_index)
{
  struct link_mem_t *cur;
  struct relay_page_entry_t *relay_page_entry = NULL;
  int i, k, found=0;

  spin_lock(&enclave_relay_page_lock);
  cur = relay_page_head;
  for (k  = 0; k < (*link_mem_index); k++)
    cur = cur->next_link_mem;
  
  i = *slab_index;
  for(; cur != NULL; cur = cur->next_link_mem)
  {
    for(; i < (cur->slab_num); ++i)
    {
      relay_page_entry = (struct relay_page_entry_t*)(cur->addr) + i;
      if((relay_page_entry->addr != 0) && enclave_name_cmp(relay_page_entry->enclave_name, enclave_name)==0)
      {
        found = 1;
        *slab_index = i+1;
        //check whether slab_index is overflow
        if ((i+1) >= (cur->slab_num))
        {
          *slab_index = 0;
          *link_mem_index = (*link_mem_index) + 1;
        }
        break;
      }
    }
    if(found)
      break;
    *link_mem_index = (*link_mem_index) + 1;
    i=0;
  }

  //haven't alloc this eid 
  if(!found)
  {
    //commented by luxu
    //sbi_printf("M mode: __get_relay_page_by_name: the relay page of this enclave is non-existed or already retrieved :%s\n", enclave_name);
    spin_unlock(&enclave_relay_page_lock);
    return NULL;
  }

  spin_unlock(&enclave_relay_page_lock);
  return relay_page_entry;
}

struct relay_page_entry_t* __list_relay_page_by_name()
{
  struct link_mem_t *cur;
  struct relay_page_entry_t *relay_page_entry = NULL;
  int i, found=0;

  cur = relay_page_head;
  
  i = 0;
  for(; cur != NULL; cur = cur->next_link_mem)
  {
    for(; i < (cur->slab_num); ++i)
    {
      relay_page_entry = (struct relay_page_entry_t*)(cur->addr) + i;
      if((relay_page_entry->addr != 0) && enclave_name_cmp(relay_page_entry->enclave_name, "")!=0)
      {
        sbi_printf("relay page name %s address %lx size %lx\n", relay_page_entry->enclave_name, relay_page_entry->addr, relay_page_entry->size);
      }
    }
    if(found)
      break;
    i=0;
  }

  //haven't alloc this eid 
  if(!found)
  {
    //commented by luxu
    //sbi_printf("M mode: __get_relay_page_by_name: the relay page of this enclave is non-existed or already retrieved :%s\n", enclave_name);
    return NULL;
  }

  return relay_page_entry;
}

/**
 * \brief  Change the relay page ownership, delete the old relay page entry in the link memory
 * and add an entry with new ownership .
 * If the relay page is not existed, reture error.
 * 
 * \param relay_page_addr: Relay page address.
 * \param relay_page_size: Relay page size.
 * \param enclave_name: The new ownership (specified by the enclave name) for the relay page.
 */
uintptr_t change_relay_page_ownership(unsigned long relay_page_addr, unsigned long relay_page_size, char *enclave_name)
{
  uintptr_t ret_val = 0;
  if ( __free_relay_page_entry( relay_page_addr,  relay_page_size) < 0)
  {
    sbi_bug("M mode: change_relay_page_ownership: can not free relay page which needs transfer the ownership\n");
    ret_val = -1;
    return ret_val;
  }

  // This relay page entry allocation can not be failed
  if (__alloc_relay_page_entry(enclave_name, relay_page_addr, relay_page_size) == NULL)
  {
    sbi_bug("M mode: change_relay_page_ownership: can not alloc relay page entry, addr is %lx\n", relay_page_addr);
  }
  // sbi_printf("reducer name %s, address %lx\n", enclave_name, relay_page_addr);
  return ret_val;
}

/**
 * \brief Swap states from host to enclaves, e.g., satp, stvec, etc.
 * 	  it is used when we run/resume enclave/shadow-encalves.
 * 
 * \param host_regs The host regs ptr.
 * \param enclave The given enclave.
 */
int swap_from_host_to_enclave(uintptr_t* host_regs, struct enclave_t* enclave)
{
  //grant encalve access to memory
  if(grant_enclave_access(enclave) < 0)
    return -1;

  //save host context
  swap_prev_state(&(enclave->thread_context), host_regs);

  //different platforms have differnt ptbr switch methods
  switch_to_enclave_ptbr(&(enclave->thread_context), enclave->thread_context.encl_ptbr);

  //save host trap vector
  swap_prev_stvec(&(enclave->thread_context), csr_read(CSR_STVEC));

  //TODO: save host cache binding
  //swap_prev_cache_binding(&enclave -> threads[0], csr_read(0x356));

  //disable interrupts
  swap_prev_mie(&(enclave->thread_context), csr_read(CSR_MIE));
  csr_read_clear(CSR_MIP, MIP_MTIP);
  csr_read_clear(CSR_MIP, MIP_STIP);
  csr_read_clear(CSR_MIP, MIP_SSIP);
  csr_read_clear(CSR_MIP, MIP_SEIP);

  //disable interrupts/exceptions delegation
  swap_prev_mideleg(&(enclave->thread_context), csr_read(CSR_MIDELEG));
  swap_prev_medeleg(&(enclave->thread_context), csr_read(CSR_MEDELEG));

  //swap the mepc to transfer control to the enclave
  swap_prev_mepc(&(enclave->thread_context), csr_read(CSR_MEPC)); 
  //set mstatus to transfer control to u mode
  uintptr_t mstatus = csr_read(CSR_MSTATUS);
  mstatus = INSERT_FIELD(mstatus, MSTATUS_MPP, PRV_U);
  csr_write(CSR_MSTATUS, mstatus);

  //mark that cpu is in enclave world now
  enter_enclave_world(enclave->eid);

  __asm__ __volatile__ ("sfence.vma" : : : "memory");
  CPU_NEED_FLUSH[current_hartid()] = 0;

  return 0;
}

/**
 * \brief Similiar to swap_from_host_to_enclave.
 * 
 * \param host_regs The host regs ptr.
 * \param enclave The given enclave.
 */
int swap_from_enclave_to_host(uintptr_t* regs, struct enclave_t* enclave)
{
  //retrieve enclave access to memory
  retrieve_enclave_access(enclave);

  //restore host context
  swap_prev_state(&(enclave->thread_context), regs);

  //restore host's ptbr
  switch_to_host_ptbr(&(enclave->thread_context), enclave->host_ptbr);

  //restore host stvec
  swap_prev_stvec(&(enclave->thread_context), csr_read(CSR_STVEC));

  //TODO: restore host cache binding
  //swap_prev_cache_binding(&(enclave->thread_context), );
  
  //restore interrupts
  swap_prev_mie(&(enclave->thread_context), csr_read(CSR_MIE));

  //restore interrupts/exceptions delegation
  swap_prev_mideleg(&(enclave->thread_context), csr_read(CSR_MIDELEG));
  swap_prev_medeleg(&(enclave->thread_context), csr_read(CSR_MEDELEG));

  //transfer control back to kernel
  swap_prev_mepc(&(enclave->thread_context), csr_read(CSR_MEPC));
  
  //restore mstatus
  uintptr_t mstatus = csr_read(CSR_MSTATUS);
  mstatus = INSERT_FIELD(mstatus, MSTATUS_MPP, PRV_S);
  csr_write(CSR_MSTATUS, mstatus);

  //mark that cpu is out of enclave world now
  exit_enclave_world();

  __asm__ __volatile__ ("sfence.vma" : : : "memory");
  CPU_NEED_FLUSH[current_hartid()] = 0;

  return 0;
}

static inline int tlb_remote_sfence()
{
  int ret;
  struct sbi_tlb_info tlb_info;
	u32 source_hart = current_hartid();
  SBI_TLB_INFO_INIT(&tlb_info, 0, 0, 0, 0,
				  SBI_TLB_FLUSH_VMA, source_hart);
  spin_lock(&cpu_in_critical_lock);
  for (int i=0; i<MAX_HARTS; i++)
  {
    if ((CPU_IN_CRITICAL & (1<<i)) == 0)
    {
      CPU_FLUSH_TAG = SET_FLUSH_TAG(i);
      CPU_NEED_FLUSH[i] = 1;
    }
  }
  spin_unlock(&cpu_in_critical_lock);
	ret = sbi_tlb_request(CPU_IN_CRITICAL&(~(1<<source_hart)), 0, &tlb_info);
  return ret;
}

/**
 * \brief The auxiliary function for the enclave call.
 * 
 * \param regs The reg argument.
 * \param top_caller_enclave The toppest enclave in the enclave calling stack.
 * \param caller_enclave The caller enclave.
 * \param callee_enclave The callee enclave.
 */
static int __enclave_call(uintptr_t* regs, struct enclave_t* top_caller_enclave, struct enclave_t* caller_enclave, struct enclave_t* callee_enclave)
{
  //move caller's host context to callee's host context
  uintptr_t encl_ptbr = callee_enclave->thread_context.encl_ptbr;
  sbi_memcpy((void*)(&(callee_enclave->thread_context)), (void*)(&(caller_enclave->thread_context)), sizeof(struct thread_state_t));
  callee_enclave->thread_context.encl_ptbr = encl_ptbr;
  callee_enclave->host_ptbr = caller_enclave->host_ptbr;
  callee_enclave->ocall_func_id = caller_enclave->ocall_func_id;
  callee_enclave->ocall_arg0 = caller_enclave->ocall_arg0;
  callee_enclave->ocall_arg1 = caller_enclave->ocall_arg1;
  callee_enclave->ocall_syscall_num = caller_enclave->ocall_syscall_num; 
  //callee_enclave->retval = caller_enclave->retval;

  //save caller's enclave context on its prev_state
  swap_prev_state(&(caller_enclave->thread_context), regs);
  caller_enclave->thread_context.prev_stvec = csr_read(CSR_STVEC);
  caller_enclave->thread_context.prev_mie = csr_read(CSR_MIE);
  caller_enclave->thread_context.prev_mideleg = csr_read(CSR_MIDELEG);
  caller_enclave->thread_context.prev_medeleg = csr_read(CSR_MEDELEG);
  caller_enclave->thread_context.prev_mepc = csr_read(CSR_MEPC);

  //clear callee's enclave context
  sbi_memset((void*)regs, 0, sizeof(struct general_registers_t));

  //different platforms have differnt ptbr switch methods
  switch_to_enclave_ptbr(&(callee_enclave->thread_context), callee_enclave->thread_context.encl_ptbr);

  //callee use caller's stvec

  //callee use caller's cache binding

  //callee use caller's mie/mip
  csr_read_clear(CSR_MIP, MIP_MTIP);
  csr_read_clear(CSR_MIP, MIP_STIP);
  csr_read_clear(CSR_MIP, MIP_SSIP);
  csr_read_clear(CSR_MIP, MIP_SEIP);

  //callee use caller's interrupts/exceptions delegation

  //transfer control to the callee enclave
  csr_write(CSR_MEPC, callee_enclave->entry_point);

  //callee use caller's mstatus

  //mark that cpu is in callee enclave world now
  enter_enclave_world(callee_enclave->eid);

  top_caller_enclave->cur_callee_eid = callee_enclave->eid;
  caller_enclave->cur_callee_eid = callee_enclave->eid;
  callee_enclave->caller_eid = caller_enclave->eid;
  callee_enclave->top_caller_eid = top_caller_enclave->eid;

  __asm__ __volatile__ ("sfence.vma" : : : "memory");
  CPU_NEED_FLUSH[current_hartid()] = 0;

  return 0;
}

/**
 * \brief The auxiliary function for the enclave return.
 * 
 * \param regs The reg argument.
 * \param top_caller_enclave The toppest enclave in the enclave calling stack.
 * \param caller_enclave The caller enclave.
 * \param callee_enclave The callee enclave.
 */
static int __enclave_return(uintptr_t* regs, struct enclave_t* callee_enclave, struct enclave_t* caller_enclave, struct enclave_t* top_caller_enclave)
{
  //restore caller's context
  sbi_memcpy((void*)regs, (void*)(&(caller_enclave->thread_context.prev_state)), sizeof(struct general_registers_t));
  swap_prev_stvec(&(caller_enclave->thread_context), callee_enclave->thread_context.prev_stvec);
  swap_prev_mie(&(caller_enclave->thread_context), callee_enclave->thread_context.prev_mie);
  swap_prev_mideleg(&(caller_enclave->thread_context), callee_enclave->thread_context.prev_mideleg);
  swap_prev_medeleg(&(caller_enclave->thread_context), callee_enclave->thread_context.prev_medeleg);
  swap_prev_mepc(&(caller_enclave->thread_context), callee_enclave->thread_context.prev_mepc);
  //restore caller's host context
  sbi_memcpy((void*)(&(caller_enclave->thread_context.prev_state)), (void*)(&(callee_enclave->thread_context.prev_state)), sizeof(struct general_registers_t));

  //clear callee's enclave context
  uintptr_t encl_ptbr = callee_enclave->thread_context.encl_ptbr;
  sbi_memset((void*)(&(callee_enclave->thread_context)), 0, sizeof(struct thread_state_t));
  callee_enclave->thread_context.encl_ptbr = encl_ptbr;
  callee_enclave->host_ptbr = 0;
  callee_enclave->ocall_func_id = NULL;
  callee_enclave->ocall_arg0 = NULL;
  callee_enclave->ocall_arg1 = NULL;
  callee_enclave->ocall_syscall_num = NULL;
  callee_enclave->retval = NULL;

  //different platforms have differnt ptbr switch methods
  switch_to_enclave_ptbr(&(caller_enclave->thread_context), caller_enclave->thread_context.encl_ptbr);

  csr_read_clear(CSR_MIP, MIP_MTIP);
  csr_read_clear(CSR_MIP, MIP_STIP);
  csr_read_clear(CSR_MIP, MIP_SSIP);
  csr_read_clear(CSR_MIP, MIP_SEIP);

  //mark that cpu is in caller enclave world now
  enter_enclave_world(caller_enclave->eid);
  top_caller_enclave->cur_callee_eid = caller_enclave->eid;
  caller_enclave->cur_callee_eid = -1;
  callee_enclave->caller_eid = -1;
  callee_enclave->top_caller_eid = -1;

  __asm__ __volatile__ ("sfence.vma" : : : "memory");
  CPU_NEED_FLUSH[current_hartid()] = 0;

  return 0;
}

/**
 * \brief free a list of memory (pma) indicated by pm_area_struct.
 * 	  the pages are zero-filled and turned back to host.
 * 
 * \param pma The pma structure of the free memory. 
 */
void free_enclave_memory(struct pm_area_struct *pma)
{
  uintptr_t paddr = 0;
  uintptr_t size = 0;

  extern spinlock_t mbitmap_lock;
  spin_lock(&mbitmap_lock);

  while(pma)
  {
    paddr = pma->paddr;
    size = pma->size;
    pma = pma->pm_next;
    //we can not clear the first page as it will be used to free mem by host
    sbi_memset((void*)(paddr + RISCV_PGSIZE), 0, size - RISCV_PGSIZE);
    __free_secure_memory(paddr, size);
  }

  spin_unlock(&mbitmap_lock);
}

void initilze_va_struct(struct pm_area_struct* pma, struct vm_area_struct* vma, struct enclave_t* enclave)
{
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
  enclave->sec_shm_vma = NULL;
}

void state_migration(struct enclave_t *enclave, struct enclave_t *parent, unsigned long migrate_arg)
{
  if (!parent || !migrate_arg)
    return;
  unsigned i, remain_page_size;
  uintptr_t vaddr, paddr;
  uintptr_t copy_to_va;
  void *copy_to_pa;
  uintptr_t copy_from_va; 
  void *copy_from_pa;
  struct pm_area_struct *pma;
  struct vm_area_struct *vma;
  /**
   * Theres' a mysterious sbug. 
   * Allocated to copy_buf (on stack) will cause Store/AMO access fault (mcause = 0x7; mtval = 0x0) sometimes.
   * But if we reuse the similar [buffer] variable on stack, this bug vanished?
   *  by Anonymous Author @ May 26, 2023. 
  */
  // char copy_buf[PAGE_SIZE];
  // char buffer[PAGE_SIZE]; // larger than sizeof(state)
  snapshot_state_t state;

  sbi_memcpy((void *)(&state), (void *)(parent->kbuffer+sizeof(ocall_create_param_t)), sizeof(snapshot_state_t));

  snapshot_mmap_state_t *mmap_state = &(state.mmap);
  snapshot_heap_state_t *heap_state = &(state.heap);

  /* register copy */
  sbi_memcpy((void *)(&(enclave->thread_context)), (void *)(&(state.regs)), sizeof(ocall_request_dump_t));
  /* stack copy */
  copy_to_va = STACK_POINT;
  for (i = 0 ; i < state.stack_sz ; i++)
  {
    vaddr = state.stack[i];
    paddr = state.stack_pa[i];

    copy_from_va = state.stack[i];
    if ((copy_from_va & (PAGE_SIZE-1)) != 0)
    {
      sbi_bug("M mode: stack address should be page-aligned.\n");
      return;
    }
    copy_from_pa = va_to_pa((uintptr_t *)(parent->root_page_table), (void *)copy_from_va);
    if (!copy_from_pa)
    {
      sbi_bug("M mode: state_migration: copy_from_va [%lx] can not be accessed\n", copy_from_va);
      return;
    }

    copy_to_va -= PAGE_SIZE;  // from high to low
    copy_to_pa = (void *)(paddr+PAGE_SIZE);
    sbi_memcpy(copy_to_pa, copy_from_pa, PAGE_SIZE);
    if (check_and_set_secure_memory(paddr, PAGE_SIZE<<1) < 0)
    {
      sbi_bug("M mode: state_migration: check_secure_memory(0x%lx, 0x%lx) failed\n", state.stack_pa[i], PAGE_SIZE<<1);
      return;
    }
    pma = (struct pm_area_struct *)(paddr);
    vma = (struct vm_area_struct *)(paddr + sizeof(struct pm_area_struct));
    pma->paddr = paddr;
    pma->size = PAGE_SIZE << 1;
    pma->pm_next = NULL;

    vma->va_start = copy_to_va;
    vma->va_end = copy_to_va + PAGE_SIZE;
    vma->vm_next = NULL;
    vma->pma = pma;
    if (insert_vma(&(enclave->stack_vma), vma, ENCLAVE_DEFAULT_STACK_BASE) < 0)
    {
      sbi_bug("[sm] [stack] insert vma failed.\n");
    }
    insert_pma(&(enclave->pma_list), pma);
    mmap((uintptr_t *)(enclave->root_page_table), &(enclave->free_pages), copy_to_va, (unsigned long)(copy_to_pa), PAGE_SIZE);

    void *test_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(STACK_POINT - PAGE_SIZE));
    if (!test_pa)
    {
      sbi_printf("[sm] mmap stack failed\n");
    }
  }


  /* mmap copy */
  for (i = 0 ; i < mmap_state->mmap_sz ; i++)
  {
    vaddr = mmap_state->mmap_areas[i].start;  // vaddr: restore the vma of destroyed NE.
    paddr = mmap_state->mmap_areas[i].paddr;
    copy_from_va = mmap_state->mmap_areas[i].vaddr; // .vaddr: save the vaddr in PE
    copy_from_pa = va_to_pa((uintptr_t *)(parent->root_page_table), (void *)copy_from_va);
    copy_to_va = vaddr;
    copy_to_pa = (void *)(paddr+PAGE_SIZE);

    if (!copy_from_pa)
    {
      sbi_bug("M mode: state_migration: copy_from_va [%lx] can not be accessed\n", copy_from_va);
      return;    
    }

    remain_page_size = PAGE_SIZE - (copy_from_va & (PAGE_SIZE-1));
    if (remain_page_size < PAGE_SIZE)
    {
      sbi_memcpy(copy_to_pa, copy_from_pa, remain_page_size);
      sbi_memcpy(copy_to_pa+remain_page_size,
                 va_to_pa((uintptr_t *)(parent->root_page_table), (void *)(copy_from_va+remain_page_size)),
                 PAGE_SIZE-remain_page_size);
    }
    else 
    {
      sbi_memcpy(copy_to_pa, copy_from_pa, PAGE_SIZE);
    }
    if (check_and_set_secure_memory(paddr, PAGE_SIZE<<1) < 0)
    {
      sbi_bug("M mode: state_migration: check_secure_memory(0x%lx, 0x%lx) failed\n", state.stack_pa[i], PAGE_SIZE<<1);
      return;
    }
    pma = (struct pm_area_struct *)(paddr);
    vma = (struct vm_area_struct *)(paddr + sizeof(struct pm_area_struct));
    pma->paddr = paddr;
    pma->size = PAGE_SIZE << 1;
    pma->pm_next = NULL;

    vma->va_start = vaddr;
    vma->va_end = vaddr + PAGE_SIZE;
    vma->vm_next = NULL;
    vma->pma = pma;
    if (insert_vma(&(enclave->stack_vma), vma, ENCLAVE_DEFAULT_MMAP_BASE) < 0)
    {
      sbi_bug("[sm] insert vma failed.\n");
    }
    insert_pma(&(enclave->pma_list), pma);
    mmap((uintptr_t *)(enclave->root_page_table), &(enclave->free_pages), vma->va_start, paddr+PAGE_SIZE, PAGE_SIZE);
  }
  /* heap copy */
  for (i = 0 ; i < heap_state->heap_sz ; i++)
  {
    vaddr = heap_state->heap_areas[i].start;
    paddr = heap_state->heap_areas[i].paddr;
    copy_from_va = heap_state->heap_areas[i].vaddr;
    copy_from_pa = va_to_pa((uintptr_t *)(parent->root_page_table), (void *)copy_from_va);
    copy_to_va = vaddr;
    copy_to_pa = (void *)(paddr+PAGE_SIZE);

    if (!copy_from_pa)
    {
      sbi_bug("M mode: state_migration: copy_from_va [%lx] can not be accessed\n", copy_from_va);
      return;    
    }

    remain_page_size = PAGE_SIZE - (copy_from_va & (PAGE_SIZE-1));
    if (remain_page_size < PAGE_SIZE)
    {
      sbi_memcpy(copy_to_pa, copy_from_pa, remain_page_size);
      sbi_memcpy(copy_to_pa+remain_page_size,
                 va_to_pa((uintptr_t *)(parent->root_page_table), (void *)(copy_from_va+remain_page_size)),
                 PAGE_SIZE-remain_page_size);
    }
    else 
    {
      sbi_memcpy(copy_to_pa, copy_from_pa, PAGE_SIZE);
    }
    if (check_and_set_secure_memory(paddr, PAGE_SIZE<<1) < 0)
    {
      sbi_bug("M mode: state_migration: check_secure_memory(0x%lx, 0x%lx) failed\n", state.stack_pa[i], PAGE_SIZE<<1);
      return;
    }
    pma = (struct pm_area_struct *)(paddr);
    vma = (struct vm_area_struct *)(paddr + sizeof(struct pm_area_struct));
    pma->paddr = paddr;
    pma->size = PAGE_SIZE << 1;
    pma->pm_next = NULL;

    vma->va_start = vaddr;
    vma->va_end = vaddr + PAGE_SIZE;
    vma->pma = pma;
    vma->vm_next = enclave->heap_vma;
    enclave->heap_vma = vma;
    if (vma->va_end > enclave->_heap_top)
    {
      enclave->_heap_top = vma->va_end;
    }
    insert_pma(&(enclave->pma_list), pma);
    mmap((uintptr_t *)(enclave->root_page_table), &(enclave->free_pages), vma->va_start, paddr+PAGE_SIZE, PAGE_SIZE);
  }
  
}

/**************************************************************/
/*                   called by host                           */
/**************************************************************/

/**
 * \brief Create a new enclave with the create_args.
 * 
 * \param create_args The arguments for creating a new enclave. 
 */
uintptr_t create_enclave(enclave_create_param_t create_args)
{
  struct enclave_t* enclave = NULL;
  struct enclave_t* parent = NULL;
  struct pm_area_struct* pma = NULL;
  struct vm_area_struct* vma = NULL;
  uintptr_t ret = 0, free_mem = 0;
  int need_free_secure_memory = 0;

  if(!enable_enclave())
  {
    ret = ENCLAVE_ERROR;
    sbi_bug("M mode: %s: cannot enable enclave \n", __func__);
    goto failed;
  }

  acquire_enclave_metadata_lock();

  //check enclave memory layout
  if(check_and_set_secure_memory(create_args.paddr, create_args.size) != 0)
  {
    ret = ENCLAVE_ERROR;
    sbi_bug("M mode: %s: check and set secure memory is failaed\n", __func__);
    goto failed;
  }
  need_free_secure_memory = 1;

  //check enclave memory layout
  if(check_enclave_layout(create_args.paddr + RISCV_PGSIZE, 0, -1UL, create_args.paddr, create_args.paddr + create_args.size) != 0)
  {
    ret = ENCLAVE_ERROR;
    sbi_bug("M mode: %s: check memory layout is failed\n", __func__);
    goto failed;
  }

  enclave = __alloc_enclave();

  release_enclave_metadata_lock();

  if(!enclave)
  {
    ret = ENCLAVE_NO_MEM;
    //commented by luxu
    //sbi_printf("M mode: %s: alloc enclave is failed \n", __func__);
    goto failed;
  }

  SET_ENCLAVE_METADATA(create_args.entry_point, enclave, &create_args, enclave_create_param_t *, paddr);

  if (enclave->type != NORMAL_ENCLAVE && enclave->type != PRIVIL_ENCLAVE)
  {
    sbi_bug("M mode: unexpected enclave type\n");
  }

  acquire_enclave_metadata_lock();

  if (enclave->parent_eid != NULL_EID)
  {
    parent = __get_enclave(enclave->parent_eid);
    if (!parent)
    {
      ret = ENCLAVE_ERROR;
      sbi_bug("M mode: cannot access parent enclave [%lu]\n", enclave->parent_eid);
      goto release_and_fail;
    }
    if (parent->type != PRIVIL_ENCLAVE || parent->state < FRESH)
    {
      ret = ENCLAVE_ERROR;
      sbi_bug("M mode: illegal parent [%lu]\n", enclave->parent_eid);
      goto release_and_fail;
    }

    if (__get_children(enclave->eid, parent->children_metadata_head) != NULL)
    {
      ret = ENCLAVE_ERROR;
      sbi_bug("M mode: children [%u] has existed in parent [%lu]\n", enclave->eid, enclave->parent_eid);
      goto release_and_fail;
    }
    
    uintptr_t address;
    struct children_enclave_t *children_enclave = __alloc_children(parent->children_metadata_head, 
                                                                  parent->children_metadata_tail, &address);
    /* call penglai_extend_secure_memory() to alloc new mm_region */
    if (!children_enclave)
    {
      ret = ENCLAVE_NO_MEM;
      // sbi_bug("M mode: __alloc_children no enough memory\n");
      goto release_and_fail;
    }
    children_enclave->eid = enclave->eid;

    parent->children_metadata_head = (struct link_mem_t*)address;
    parent->children_metadata_tail = (struct link_mem_t*)address;
  }
  
  release_enclave_metadata_lock();

  //traverse vmas
  pma = (struct pm_area_struct*)(create_args.paddr);
  vma = (struct vm_area_struct*)(create_args.paddr + sizeof(struct pm_area_struct));
  pma->paddr = create_args.paddr;
  pma->size = create_args.size;
  pma->free_mem = create_args.free_mem;
  if(pma->free_mem < pma->paddr || pma->free_mem >= pma->paddr+pma->size
      || pma->free_mem & ((1<<RISCV_PGSHIFT) - 1))
  {
    ret = ENCLAVE_ERROR;
    sbi_bug("M mode: %s: pma free_mem is failed\n", __func__);
    goto failed;
  }

  initilze_va_struct(pma, vma, enclave);

  enclave->free_pages = NULL;
  enclave->free_pages_num = 0;
  free_mem = create_args.paddr + create_args.size - RISCV_PGSIZE;
  enclave->ocalling_shm_key = -1UL;
  // Reserve the first two entries for free memory page
  while(free_mem >= create_args.free_mem)
  {
    struct page_t *page = (struct page_t*)free_mem;
    page->paddr = free_mem;
    page->next = enclave->free_pages;
    enclave->free_pages = page;
    enclave->free_pages_num += 1;
    free_mem -= RISCV_PGSIZE;
  }
  //check kbuffer
  if(create_args.kbuffer_size < RISCV_PGSIZE || create_args.kbuffer & (RISCV_PGSIZE-1) || create_args.kbuffer_size & (RISCV_PGSIZE-1))
  {
    ret = ENCLAVE_ERROR;
    sbi_bug("M mode: %s: kbuffer check is failed\n", __func__);
    goto failed;
  }
  mmap((uintptr_t*)(enclave->root_page_table), &(enclave->free_pages), ENCLAVE_DEFAULT_KBUFFER, create_args.kbuffer, create_args.kbuffer_size);

  //check shm
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
  /* todo. add our create-from-snapshot here. */
  if (enclave->parent_eid != NULL_EID)
  {
    struct enclave_t *parent = __get_enclave(enclave->parent_eid);
    state_migration(enclave, parent, create_args.migrate_arg);
  }


  hash_enclave(enclave, (void*)(enclave->hash), 0);
  copy_word_to_host((unsigned int*)create_args.eid_ptr, enclave->eid);
  //Sync and flush the remote TLB entry.
  tlb_remote_sfence();
  return ret;

release_and_fail:
  release_enclave_metadata_lock();
failed:
  if(need_free_secure_memory)
  {
    free_secure_memory(create_args.paddr, create_args.size);
  }
  if(enclave)
  {
    __free_enclave(enclave->eid);
  }
  return ret;
}

/**
 * \brief Create a new shadow enclave with the create_args.
 * 
 * \param create_args The arguments for creating a new shadow enclave. 
 */
uintptr_t create_shadow_enclave(enclave_create_param_t create_args)
{
  uintptr_t ret = 0;
  int need_free_secure_memory = 0;
  acquire_enclave_metadata_lock();
  eapp_args = 0;
  if(!enable_enclave())
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
  struct shadow_enclave_t* shadow_enclave;
  shadow_enclave = __alloc_shadow_enclave();

  release_enclave_metadata_lock();
  if(!shadow_enclave)
  {
    //commented by luxu
    // sbi_printf("M mode: create shadow enclave: no enough memory to alloc_shadow_enclave\n");
    ret = ENCLAVE_NO_MEM;
    goto failed;
  }
  shadow_enclave->entry_point = create_args.entry_point;
  //first page is reserve for page link
  shadow_enclave->root_page_table = create_args.paddr + RISCV_PGSIZE;
  shadow_enclave->thread_context.encl_ptbr = ((create_args.paddr+RISCV_PGSIZE) >> RISCV_PGSHIFT) | SATP_MODE_CHOICE;
  shadow_enclave->paddr = create_args.paddr;
  shadow_enclave->size = create_args.size;

  hash_shadow_enclave(shadow_enclave, (void*)(shadow_enclave->hash), 0);
  copy_word_to_host((unsigned int*)create_args.eid_ptr, shadow_enclave->eid);
  
  //Sync and flush the remote TLB entry.
  tlb_remote_sfence();
  return ret;

failed:
  if(need_free_secure_memory)
  {
    free_secure_memory(create_args.paddr, create_args.size);
  }
  return ret;
}

/**
 * \brief Host calls this function to destroy the shadow enclave.
 * 
 * \param regs The host register context.
 * \param eid Destroyed shadow enclave id.
 */
uintptr_t destroy_shadow_enclave(uintptr_t* regs, unsigned int eid)
{
  uintptr_t retval = 0;
  struct shadow_enclave_t* shadow_enclave;
  acquire_enclave_metadata_lock();

  shadow_enclave = __get_shadow_enclave(eid);

  if(!shadow_enclave)
  {
    sbi_bug("M mode: destroy_shadow_enclave: shadow_enclave%d can not be accessed\n", eid);
    retval = -1UL;
    goto destroy_enclave_out;
  }

  // Free the secure memory size
  free_secure_memory(shadow_enclave->paddr, shadow_enclave->size);
  // Free the shadow enclave metadata
  __free_shadow_enclave(eid);

destroy_enclave_out:
  release_enclave_metadata_lock();

  return retval;
}

uintptr_t map_relay_page(unsigned int eid, uintptr_t mm_arg_addr, uintptr_t mm_arg_size, uintptr_t* mmap_offset, struct enclave_t* enclave, struct relay_page_entry_t* relay_page_entry)
{
  uintptr_t retval = 0;
  // If the mm_arg_size is zero but mm_arg_addr is not zero, it means the relay page is transfer from other enclave 
  if(mm_arg_addr && !mm_arg_size)
  {
    int slab_index = 0, link_mem_index = 0, kk = 0;
    if(check_enclave_name(enclave->enclave_name, eid) < 0)
    {
      sbi_bug("M mode：map_relay_page: check enclave name is failed\n");
      retval = -1UL;
      return retval;
    }
    while((relay_page_entry = __get_relay_page_by_name(enclave->enclave_name, &slab_index, &link_mem_index)) != NULL)
    {
      mmap((uintptr_t*)(enclave->root_page_table), &(enclave->free_pages), ENCLAVE_DEFAULT_MM_ARG_BASE + *mmap_offset, relay_page_entry->addr, relay_page_entry->size);
      *mmap_offset = *mmap_offset + relay_page_entry->size;
      if (enclave->mm_arg_paddr[0] == 0)
      {
        enclave->mm_arg_paddr[kk] = relay_page_entry->addr;
        enclave->mm_arg_size[kk] = relay_page_entry->size;
      }
      else
      {
        // enclave->mm_arg_size = enclave->mm_arg_size + relay_page_entry->size;
        enclave->mm_arg_paddr[kk] = relay_page_entry->addr;
        enclave->mm_arg_size[kk] = relay_page_entry->size;
      }
      kk = kk + 1;
    }
    if ((relay_page_entry == NULL) && (enclave->mm_arg_paddr[0] == 0))
    {
      sbi_bug("M mode: map_relay_page: get relay page by name is failed \n");
      retval = -1UL;
      return retval;
    }
  }
  else if(mm_arg_addr && mm_arg_size)
  {
    //check whether the enclave name is duplicated
    if (check_enclave_name(enclave->enclave_name, eid) < 0)
    {
      sbi_bug("M mode：map_relay_page: check enclave name is failed\n");
      retval = -1UL;
      return retval;
    }
    if (__alloc_relay_page_entry(enclave->enclave_name, mm_arg_addr, mm_arg_size) ==NULL)
    {
      //commented by luxu
      // sbi_debug("M mode: map_relay_page: lack of the secure memory for the relay page entries\n");
      retval = ENCLAVE_NO_MEM;
      return retval;
    }
    //check the relay page is not mapping in other enclave, and unmap the relay page for host
    if(check_and_set_secure_memory(mm_arg_addr, mm_arg_size) != 0)
    {
      sbi_bug("M mode: map_relay_page: check_and_set_secure_memory is failed\n");
      retval = -1UL;
      return retval;
    }
    enclave->mm_arg_paddr[0] = mm_arg_addr;
    enclave->mm_arg_size[0] = mm_arg_size;
    *mmap_offset = mm_arg_size;
    mmap((uintptr_t*)(enclave->root_page_table), &(enclave->free_pages), ENCLAVE_DEFAULT_MM_ARG_BASE, mm_arg_addr, mm_arg_size);
    
  }

  return retval;
}

/**
 * \brief Run the enclave with the given eid and running parameters.
 * 
 * \param regs The host reg need to save.
 * \param eid The given enclave id.
 * \param mm_arg_addr The relay page address for this enclave, map before enclave run.
 * \param mm_arg_size The relay page size for this enclave, map before enclave run.  
 */
uintptr_t run_enclave(uintptr_t* regs, unsigned int eid, enclave_run_param_t enclave_run_param)
{
  struct enclave_t* enclave;
  uintptr_t retval = 0, mmap_offset = 0;
  uintptr_t mm_arg_addr = enclave_run_param.mm_arg_addr;
  uintptr_t mm_arg_size = enclave_run_param.mm_arg_size;
  struct relay_page_entry_t* relay_page_entry = NULL;

  acquire_enclave_metadata_lock();

  enclave = __get_enclave(eid);

  release_enclave_metadata_lock();
  /* todo: extend our sanity check here. */
  if(!enclave || enclave->state != FRESH || enclave->type == SERVER_ENCLAVE)
  {
    sbi_bug("M mode: run_enclave: enclave%d can not be accessed!\n", eid);
    retval = -1UL;
    goto run_enclave_out;
  }

  /** We bind a host process (host_ptbr) during run_enclave, which will be checked during resume */
  enclave->host_ptbr = csr_read(CSR_SATP);
  
  if (enclave->parent_eid == NULL_EID)
  {
    if((retval =map_relay_page(eid, mm_arg_addr, mm_arg_size, &mmap_offset, enclave, relay_page_entry)) != 0)
    {
      if (retval == ENCLAVE_NO_MEM)
        goto run_enclave_out;
      else
        goto run_enclave_out;
    }
    //the relay page is transfered from another enclave
  }



  if(swap_from_host_to_enclave(regs, enclave) < 0)
  {
    sbi_bug("M mode: run_enclave: enclave can not be run\n");
    retval = -1UL;
    goto run_enclave_out;
  }

  //set return address to enclave
  csr_write(CSR_MEPC, (uintptr_t)(enclave->entry_point));

  //enable timer interrupt
  csr_read_set(CSR_MIE, MIP_MTIP);
  csr_read_set(CSR_MIE, MIP_MSIP);

  //set default stack
  regs[2] = ENCLAVE_DEFAULT_STACK_BASE;

  //pass parameters
  if(enclave->shm_paddr)
    regs[10] = ENCLAVE_DEFAULT_SHM_BASE;
  else
    regs[10] = 0;
  retval = regs[10];
  regs[11] = enclave->shm_size;
  regs[12] = eapp_args;
  if(enclave->mm_arg_paddr[0])
    regs[13] = ENCLAVE_DEFAULT_MM_ARG_BASE;
  else
    regs[13] = 0;
  regs[14] = mmap_offset;
  // sbi_debug("enclave %d mpec %lx running\n", eapp_args, (enclave->entry_point));
  eapp_args = eapp_args+1;

  enclave->state = RUNNING;
run_enclave_out:
  tlb_remote_sfence();
  return retval;
}

/**
 * \brief Fork an enclave instance from shodow enclave and run this enclave instance immediately.
 * 
 * \param regs The host reg need to save.
 * \param eid The given shadow enclave id.
 * \param enclave_run_param The parameter for run a shadow enclave.
 * \param mm_arg_addr The relay page address for this enclave, map before enclave run.
 * \param mm_arg_size The relay page size for this enclave, map before enclave run.  
 */
uintptr_t run_shadow_enclave(uintptr_t* regs, unsigned int eid, shadow_enclave_run_param_t enclave_run_param)
{
  struct enclave_t* enclave = NULL;
  struct shadow_enclave_t* shadow_enclave = NULL;
  struct relay_page_entry_t* relay_page_entry = NULL;
  struct pm_area_struct* pma = NULL;
  struct vm_area_struct* vma = NULL;
  uintptr_t retval = 0, mmap_offset = 0, free_mem = 0;
  uintptr_t mm_arg_addr = enclave_run_param.mm_arg_addr;
  uintptr_t mm_arg_size = enclave_run_param.mm_arg_size;
  int need_free_secure_memory = 0, copy_page_table_ret = 0;

  acquire_enclave_metadata_lock();
  shadow_enclave = __get_shadow_enclave(eid);
  enclave = __alloc_enclave();
  release_enclave_metadata_lock();

  if(!enclave)
  {
    sbi_bug("create enclave from shadow enclave is failed\n");
    retval = ENCLAVE_NO_MEM;
    goto run_enclave_out;
  }

  if(check_and_set_secure_memory(enclave_run_param.free_page, enclave_run_param.size) != 0)
  {
    retval = ENCLAVE_ERROR;
    goto run_enclave_out;
  }
  need_free_secure_memory = 1;

  enclave->free_pages = NULL;
  enclave->free_pages_num = 0;
  free_mem = enclave_run_param.free_page + enclave_run_param.size - 2*RISCV_PGSIZE;
  
  // Reserve the first two entries in the free pages
  while(free_mem >= enclave_run_param.free_page + 2*RISCV_PGSIZE)
  {
    struct page_t *page = (struct page_t*)free_mem;
    page->paddr = free_mem;
    page->next = enclave->free_pages;
    enclave->free_pages = page;
    enclave->free_pages_num += 1;
    free_mem -= RISCV_PGSIZE;
  }

  copy_page_table_ret = __copy_page_table((pte_t*) (shadow_enclave->root_page_table), &(enclave->free_pages), 2, (pte_t*)(enclave_run_param.free_page + RISCV_PGSIZE));
  if (copy_page_table_ret < 0)
  {
    sbi_bug("copy_page_table fail\n");
    retval = ENCLAVE_ERROR;
    goto run_enclave_out;
  }

  copy_page_table_ret =  map_empty_page((uintptr_t*)(enclave_run_param.free_page + RISCV_PGSIZE), &(enclave->free_pages), ENCLAVE_DEFAULT_STACK_BASE-ENCLAVE_DEFAULT_STACK_SIZE, ENCLAVE_DEFAULT_STACK_SIZE);
  if (copy_page_table_ret < 0)
  {
    sbi_bug("alloc stack for shadow enclave fail\n");
    sbi_bug("M mode: shadow_enclave_run: ENCLAVE_DEFAULT_STACK_SIZE is larger than the free memory size \n");
    retval = ENCLAVE_ERROR;
    goto run_enclave_out;
  }

  SET_SHADOW_ENCLAVE_METADATA(shadow_enclave->entry_point, enclave, &enclave_run_param, shadow_enclave_run_param_t *, free_page);

  //traverse vmas
  pma = (struct pm_area_struct*)(enclave_run_param.free_page);
  vma = (struct vm_area_struct*)(enclave_run_param.free_page + sizeof(struct pm_area_struct));
  pma->paddr = enclave_run_param.free_page;
  pma->size = enclave_run_param.size;
  pma->free_mem = enclave_run_param.free_page + 2*RISCV_PGSIZE;
  initilze_va_struct(pma, vma, enclave);

  if(enclave_run_param.kbuffer_size < RISCV_PGSIZE || enclave_run_param.kbuffer & (RISCV_PGSIZE-1) || enclave_run_param.kbuffer_size & (RISCV_PGSIZE-1))
  {
    retval = ENCLAVE_ERROR;
    goto run_enclave_out;
  }
  
  mmap((uintptr_t*)(enclave->root_page_table), &(enclave->free_pages), ENCLAVE_DEFAULT_KBUFFER, enclave_run_param.kbuffer, enclave_run_param.kbuffer_size);

  //check shm
  if(enclave_run_param.shm_paddr && enclave_run_param.shm_size &&
      !(enclave_run_param.shm_paddr & (RISCV_PGSIZE-1)) && !(enclave_run_param.shm_size & (RISCV_PGSIZE-1)))
  {
    mmap((uintptr_t*)(enclave->root_page_table), &(enclave->free_pages), ENCLAVE_DEFAULT_SHM_BASE, enclave_run_param.shm_paddr, enclave_run_param.shm_size);
    enclave->shm_paddr = enclave_run_param.shm_paddr;
    enclave->shm_size = enclave_run_param.shm_size;
  }
  else
  {
    enclave->shm_paddr = 0;
    enclave->shm_size = 0;
  }

  copy_word_to_host((unsigned int*)enclave_run_param.eid_ptr, enclave->eid);

  //map the relay page
  if((retval =map_relay_page(enclave->eid, mm_arg_addr, mm_arg_size, &mmap_offset, enclave, relay_page_entry)) != 0)
  {
    if (retval == ENCLAVE_NO_MEM)
      goto failed;
    else
      goto run_enclave_out;
  }

  // Copy the enclave measurement from the shadow enclave
  sbi_memcpy(enclave->hash, (char *)shadow_enclave->hash, HASH_SIZE);

  // __list_relay_page_by_name();
  if(swap_from_host_to_enclave(regs, enclave) < 0)
  {
    sbi_bug("M mode: run_shadow_enclave: enclave can not be run\n");
    retval = -1UL;
    goto run_enclave_out;
  }

  //set return address to enclave
  csr_write(CSR_MEPC, (uintptr_t)(enclave->entry_point));

  //enable timer interrupt
  csr_read_set(CSR_MIE, MIP_MTIP);
  csr_read_set(CSR_MIE, MIP_MSIP);

  //set default stack
  regs[2] = ENCLAVE_DEFAULT_STACK_BASE;

  //pass parameters
  if(enclave->shm_paddr)
    regs[10] = ENCLAVE_DEFAULT_SHM_BASE;
  else
    regs[10] = 0;
  retval = regs[10];
  regs[11] = enclave->shm_size;
  regs[12] = (eapp_args) % 5;
  if(enclave->mm_arg_paddr[0])
    regs[13] = ENCLAVE_DEFAULT_MM_ARG_BASE;
  else
    regs[13] = 0;
  regs[14] = mmap_offset;
  eapp_args = eapp_args+1;

  enclave->state = RUNNING;


  //commented by luxu
  //sbi_printf("M mode: run shadow enclave...\n");

run_enclave_out:
  tlb_remote_sfence();
  return retval;

failed:
  if(need_free_secure_memory)
  {
    free_secure_memory(enclave_run_param.free_page, enclave_run_param.size);
    sbi_memset((void *)enclave_run_param.free_page, 0, enclave_run_param.size);
  }
  
  if(enclave)
    __free_enclave(enclave->eid);
  return retval;
}


uintptr_t attest_enclave(uintptr_t eid, uintptr_t report_ptr, uintptr_t nonce)
{
  struct enclave_t* enclave = NULL;
  int attestable = 1;
  struct report_t report;
  enclave_state_t old_state = INVALID;
  unsigned char attest_hash[HASH_SIZE];

  acquire_enclave_metadata_lock();
  enclave = __get_enclave(eid);
  if(!enclave || (enclave->state != FRESH && enclave->state != STOPPED)
    || enclave->host_ptbr != csr_read(CSR_SATP))
    attestable = 0;
  else
  {
    old_state = enclave->state;
    enclave->state = ATTESTING;
  }
  release_enclave_metadata_lock();

  if(!attestable)
  {
    sbi_printf("M mode: attest_enclave: enclave%ld is not attestable\n", eid);
    return -1UL;
  }

  sbi_memcpy((void*)(report.dev_pub_key), (void*)DEV_PUB_KEY, PUBLIC_KEY_SIZE);
  sbi_memcpy((void*)(report.sm.hash), (void*)SM_HASH, HASH_SIZE);
  sbi_memcpy((void*)(report.sm.sm_pub_key), (void*)SM_PUB_KEY, PUBLIC_KEY_SIZE);
  sbi_memcpy((void*)(report.sm.signature), (void*)SM_SIGNATURE, SIGNATURE_SIZE);
  sbi_memcpy(attest_hash, (char *)enclave->hash, HASH_SIZE);

  update_enclave_hash((char *)(report.enclave.hash), attest_hash, nonce);
  sign_enclave((void*)(report.enclave.signature), (void*)(report.enclave.hash));
  report.enclave.nonce = nonce;

  //printHex((unsigned char*)(report.enclave.signature), 64);
  copy_to_host((void*)report_ptr, (void*)(&report), sizeof(struct report_t));

  acquire_enclave_metadata_lock();
  enclave->state = old_state;
  release_enclave_metadata_lock();
  return 0;
}

uintptr_t attest_shadow_enclave(uintptr_t eid, uintptr_t report_ptr, uintptr_t nonce)
{
  struct shadow_enclave_t* shadow_enclave = NULL;
  int attestable = 1;
  struct report_t report;
  unsigned char attest_hash[HASH_SIZE];
  
  acquire_enclave_metadata_lock();
  shadow_enclave = __get_shadow_enclave(eid);
  release_enclave_metadata_lock();

  if(!attestable)
  {
    sbi_printf("M mode: attest_enclave: enclave%ld is not attestable\n", eid);
    return -1UL;
  }

  sbi_memcpy(attest_hash, (char *)shadow_enclave->hash, HASH_SIZE);

  update_enclave_hash((char *)(report.enclave.hash), attest_hash, nonce);
  sbi_memcpy((void*)(report.dev_pub_key), (void*)DEV_PUB_KEY, PUBLIC_KEY_SIZE);
  sbi_memcpy((void*)(report.sm.hash), (void*)SM_HASH, HASH_SIZE);
  sbi_memcpy((void*)(report.sm.sm_pub_key), (void*)SM_PUB_KEY, PUBLIC_KEY_SIZE);
  sbi_memcpy((void*)(report.sm.signature), (void*)SM_SIGNATURE, SIGNATURE_SIZE);
  sign_enclave((void*)(report.enclave.signature), (void*)(report.enclave.hash));
  report.enclave.nonce = nonce;

  copy_to_host((void*)report_ptr, (void*)(&report), sizeof(struct report_t));

  return 0;
}

/**
 * \brief host use this function to wake a stopped enclave.
 * 
 * \param regs The host reg need to save.
 * \param eid The given enclave id. 
 */
uintptr_t wake_enclave(uintptr_t* regs, unsigned int eid)
{
  uintptr_t retval = 0;
  struct enclave_t* enclave = NULL;

  acquire_enclave_metadata_lock();

  enclave = __get_real_enclave(eid);
  if(!enclave || enclave->state != STOPPED || enclave->host_ptbr != csr_read(CSR_SATP))
  {
    sbi_bug("M mode: wake_enclave: enclave%d can not be accessed!\n", eid);
    retval = -1UL;
    goto wake_enclave_out;
  }

  enclave->state = RUNNABLE;
wake_enclave_out:
  release_enclave_metadata_lock();
  return retval;
}

/**
 * \brief Resume the enclave from the previous status.
 * 
 * \param regs The host reg need to save.
 * \param eid The given enclave id. 
 */
uintptr_t resume_enclave(uintptr_t* regs, unsigned int eid)
{
  uintptr_t retval = 0;
  struct enclave_t* enclave = NULL;

  acquire_enclave_metadata_lock();
  enclave = __get_real_enclave(eid);

  if(!enclave || (enclave->state <= INVALID))
  {
    sbi_printf("M mode: resume_enclave: enclave%d is not existed\n", eid);
    retval = 0UL;
    goto resume_enclave_out;
  }

  if(enclave->state <= FRESH || enclave->host_ptbr != csr_read(CSR_SATP))
  {
    sbi_bug("M mode: resume_enclave: enclave%d cannot resume state %d\n", eid, enclave->state);
    retval = -1UL;
    goto resume_enclave_out;
  }

  if(enclave->state == STOPPED)
  {
    sbi_printf("[sm] resume_enclave: enclave%d is stopped\n", eid);
    retval = ENCLAVE_TIMER_IRQ;
    goto resume_enclave_out;
  }

  if(enclave->state != RUNNABLE)
  {
    sbi_bug("M mode: resume_enclave: enclave%d is not runnable\n", eid);
    retval = -1UL;
    goto resume_enclave_out;
  }

  if(swap_from_host_to_enclave(regs, enclave) < 0)
  {
    sbi_bug("M mode: resume_enclave: enclave can not be resume\n");
    retval = -1UL;
    goto resume_enclave_out;
  }
  enclave->state = RUNNING;
  // regs[10] will be set to retval when mcall_trap return, so we have to
  // set retval to be regs[10] here to succuessfully restore context
  retval = regs[10];
resume_enclave_out:
  release_enclave_metadata_lock();
  return retval;
}

/**
 * \brief Resume the normal enclave from the previous ocall.
 * 
 * \param regs The host reg need to save.
 * \param eid The given enclave id. 
 */
uintptr_t resume_from_request(uintptr_t* regs, unsigned int eid)
{
  uintptr_t retval = 0;
  struct enclave_t* enclave = NULL;
  acquire_enclave_metadata_lock();
  enclave = __get_real_enclave(eid);

  if(!enclave || (enclave->state <= INVALID))
  {
    sbi_printf("M mode: resume_from_request: enclave%d is not existed\n", eid);
    retval = 0UL;
    goto resume_from_req_out;
  }

  if(enclave->state <= FRESH || enclave->host_ptbr != csr_read(CSR_SATP))
  {
    sbi_bug("M mode: resume_from_request: enclave%d cannot resume state %d\n", eid, enclave->state);
    retval = -1UL;
    goto resume_from_req_out;
  }

  if(enclave->state != STOPPED)
  {
    sbi_bug("M mode: resume_from_request: enclave%d is not runnable\n", eid);
    retval = -1UL;
    goto resume_from_req_out;
  }

  /* do response */

  if(swap_from_host_to_enclave(regs, enclave) < 0)
  {
    sbi_bug("M mode: resume_from_request: enclave can not be resume\n");
    retval = -1UL;
    goto resume_from_req_out;
  }
  enclave->state = RUNNING;
  // regs[10] will be set to retval when mcall_trap return, so we have to
  // set retval to be regs[10] here to succuessfully restore context
  retval = regs[10];
resume_from_req_out:
  release_enclave_metadata_lock();
  return retval;
}
/**
 * \brief Map the enclave memory before ocall returns.
 * 
 * \param enclave The enclave structure.
 * \param paddr The mapped physical address.
 * \param size The mapped memory size.
 */
uintptr_t mmap_after_resume(struct enclave_t *enclave, uintptr_t paddr, uintptr_t size)
{
  uintptr_t retval = 0;
  //uintptr_t vaddr = ENCLAVE_DEFAULT_MMAP_BASE;
  uintptr_t vaddr = enclave->thread_context.prev_state.a1;
  if(!vaddr) vaddr = ENCLAVE_DEFAULT_MMAP_BASE - (size - RISCV_PGSIZE);
  if(check_and_set_secure_memory(paddr, size) < 0)
  {
    sbi_bug("M mode: mmap_after_resume: check_secure_memory(0x%lx, 0x%lx) failed\n", paddr, size);
    retval = -1UL;
    return retval;
  }

  struct pm_area_struct *pma = (struct pm_area_struct*)paddr;
  struct vm_area_struct *vma = (struct vm_area_struct*)(paddr + sizeof(struct pm_area_struct));
  pma->paddr = paddr;
  pma->size = size;
  pma->pm_next = NULL;
  //vma->va_start = vaddr - (size - RISCV_PGSIZE);
  //vma->va_end = vaddr;
  vma->va_start = vaddr;
  vma->va_end = vaddr + size - RISCV_PGSIZE;
  vma->vm_next = NULL;
  vma->pma = pma;
  if(insert_vma(&(enclave->mmap_vma), vma, ENCLAVE_DEFAULT_MMAP_BASE) < 0)
  {
    vma->va_end = enclave->mmap_vma->va_start;
    vma->va_start = vma->va_end - (size - RISCV_PGSIZE);
    vma->vm_next = enclave->mmap_vma;
    enclave->mmap_vma = vma;
  }
  insert_pma(&(enclave->pma_list), pma);
  mmap((uintptr_t*)(enclave->root_page_table), &(enclave->free_pages), vma->va_start, paddr+RISCV_PGSIZE, size-RISCV_PGSIZE);
  retval = vma->va_start;

  return retval;
}

/**
 * \brief Map the sbrk memory (heap) before ocall returns.
 * 
 * \param enclave The enclave structure.
 * \param paddr The mapped physical address.
 * \param size The mapped memory size. 
 */
uintptr_t sbrk_after_resume(struct enclave_t *enclave, uintptr_t paddr, uintptr_t size)
{
  uintptr_t retval = 0;
  intptr_t req_size = (intptr_t)(enclave->thread_context.prev_state.a1);
  if(req_size <= 0)
  {
    return enclave->_heap_top;
  }
  if(check_and_set_secure_memory(paddr, size) < 0)
  {
    retval = -1UL;
    sbi_bug("M mode: sbrk_after_resume: check and set the secure memory is failed \n");
    return retval;
  }
  
  struct pm_area_struct *pma = (struct pm_area_struct*)paddr;
  struct vm_area_struct *vma = (struct vm_area_struct*)(paddr + sizeof(struct pm_area_struct));
  pma->paddr = paddr;
  pma->size = size;
  pma->pm_next = NULL;
  vma->va_start = enclave->_heap_top;
  vma->va_end = vma->va_start + size - RISCV_PGSIZE;
  vma->vm_next = NULL;
  vma->pma = pma;
  vma->vm_next = enclave->heap_vma;
  enclave->heap_vma = vma;
  enclave->_heap_top = vma->va_end;
  insert_pma(&(enclave->pma_list), pma);
  mmap((uintptr_t*)(enclave->root_page_table), &(enclave->free_pages), vma->va_start, paddr+RISCV_PGSIZE, size-RISCV_PGSIZE);
  retval = enclave->_heap_top;

  return retval;
}

/**
 * \brief Map the relay page before ocall returns.
 * 
 * \param enclave The enclave structure.
 * \param mm_arg_addr Relay page address.
 * \param mm_arg_size Relay page size.
 */
uintptr_t return_relay_page_after_resume(struct enclave_t *enclave, uintptr_t mm_arg_addr, uintptr_t mm_arg_size)
{
  uintptr_t retval = 0, mmap_offset = 0;
  if((retval =map_relay_page(enclave->eid, mm_arg_addr, mm_arg_size, &mmap_offset, enclave, NULL)) != 0)
  {
    if (retval == ENCLAVE_NO_MEM)
      goto run_enclave_out;
    else
      goto run_enclave_out;
  }

run_enclave_out:
  tlb_remote_sfence();
  return retval;
}

/** add our after_resume function here for parameter write-back
 * by Anonymous Author @ May 13, 2023.
*/
/**
 * \brief Write the allocated eid back to PE's param
 * 
 * \param enclave The enclave structure.
 * \param vaddr The PE's param address (VA)
 * \param alloc_eid The allocated eid
 */
uintptr_t privil_create_after_resume(struct enclave_t *enclave, uintptr_t vaddr, uintptr_t alloc_eid)
{
  
  uintptr_t retval = 0;
  void *create_args = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)vaddr);
  if (!create_args)
  {
    retval = -1UL;
    sbi_bug("M mode: privil_create_after_resume: enclave%d PT can not be accessed!\n", enclave->eid);
    goto out;
  }
  ((ocall_create_param_t *)create_args)->eid = alloc_eid;
out:
  return retval;
}

/**
 * \brief Perform attestation adn write result back to PE.
 * 
 * \param enclave The enclave structure.
 * \param tgt_eid The attestee slab-layer eid
 * 
 * \details The whole function is locked, so don't need to update target enclave state as ATTESTING.
 */
uintptr_t privil_attest_after_resume(struct enclave_t *enclave, uintptr_t tgt_eid)
{
  uintptr_t retval = 0;
  int attestable = 1;
  struct report_t report;
  ocall_attest_param_t attest_args;
  struct enclave_t* tgt_enclave = NULL;
  unsigned char attest_hash[HASH_SIZE];

  sbi_memcpy(&attest_args, (void *)(enclave->kbuffer), sizeof(ocall_attest_param_t));
  tgt_enclave = __get_enclave(tgt_eid);
  if (!tgt_enclave || (tgt_enclave->state != FRESH && tgt_enclave->state != STOPPED)
      || tgt_enclave->parent_eid != enclave->eid)
    attestable = 0;
  
  if (!attestable)
  {
    sbi_printf("M mode: privil_attest_after_resume: enclave%ld is not attestable\n", tgt_eid);
    retval = -1UL;
    goto out;
  }
  /* do attestation */
  sbi_memcpy((void*)(report.dev_pub_key), (void*)DEV_PUB_KEY, PUBLIC_KEY_SIZE);
  sbi_memcpy((void*)(report.sm.hash), (void*)SM_HASH, HASH_SIZE);
  sbi_memcpy((void*)(report.sm.sm_pub_key), (void*)SM_PUB_KEY, PUBLIC_KEY_SIZE);
  sbi_memcpy((void*)(report.sm.signature), (void*)SM_SIGNATURE, SIGNATURE_SIZE);
  sbi_memcpy(attest_hash, (char *)enclave->hash, HASH_SIZE);
    
  update_enclave_hash((char *)(report.enclave.hash), attest_hash, attest_args.nonce);
  sign_enclave((void*)(report.enclave.signature), (void*)(report.enclave.hash));
  report.enclave.nonce = attest_args.nonce;

  void *report_ptr = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(attest_args.report_ptr));
  if (!report_ptr)
  {
    retval = -1UL;
    sbi_bug("M mode: privil_attest_after_resume: enclave%d PT can not be accessed!\n", enclave->eid);
    goto out;
  }
  sbi_memcpy(report_ptr, (void *)(&report), sizeof(struct report_t));

out:
  return retval;
}

/**
 * \brief Accept the reason of NE, resume its parent PE.
 * 
 * \param enclave The enclave structure.
 * \param return_reason The reason why Normal Enclave stop/crash (IRQ, Share Page, ...)
 * \param return_value The NE process's return value.
 * 
 * \details The whole function is locked, so don't need to update target enclave state as ATTESTING.
 *          EXIT_ENCLAVE won't enter this function, instead, it will enter sm_exit_enclave().
 * \details For NE requests, the detailed request reason is saved in \param return_reason,
 *          and the request address (VA) is saved in \param return_value.
 * 
 */
uintptr_t privil_run_after_resume(struct enclave_t *enclave, uintptr_t return_reason, uintptr_t return_value)
{
  uintptr_t ret = 0;
  int return_reason_int = return_reason;
  int return_value_int = return_value;
  ocall_run_param_t run_args;
  struct enclave_t *tgt_enclave = NULL;
  sbi_memcpy(&run_args, (void *)(enclave->kbuffer), sizeof(ocall_run_param_t));
  
  tgt_enclave = __get_enclave(run_args.run_eid);
  if (!tgt_enclave)
  {
    sbi_bug("M mode: privil_run_after_resume: enclave%d is not valid\n", run_args.run_eid);
    ret = -1UL; goto out;
  }
  if (tgt_enclave->state > FRESH && tgt_enclave->parent_eid != enclave->eid)
  {
    sbi_bug("M mode: privil_run_after_resume: [%d] will returns to an unmatched parent [%d]. Expected: [%ld]", 
                     run_args.run_eid, enclave->eid, tgt_enclave->parent_eid);
    ret = -1UL; goto out;
  }

  void *reason_ptr = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(run_args.reason_ptr));
  if (!reason_ptr)
  {
    ret = -1UL;
    sbi_bug("M mode: privil_attest_after_resume: enclave%d PT can not be accessed!\n", enclave->eid);
  }
  sbi_memcpy(reason_ptr, (void *)(&return_reason_int), sizeof(int));

  void *retval_ptr = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(run_args.retval_ptr));
  if (!retval_ptr)
  {
    ret = -1UL;
    sbi_bug("M mode: privil_attest_after_resume: enclave%d PT can not be accessed!\n", enclave->eid);
  }
  sbi_memcpy(retval_ptr, (void *)(&return_value_int), sizeof(int));
  

  /* handle Request from Normal Enclave, load its request and write it into PE's running param. */
  uintptr_t ne_request_arg = return_value;
  void *ne_request_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(ne_request_arg));
  void *pe_request_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(run_args.request_arg));
  ocall_request_t *ne_request = (ocall_request_t *)ne_request_pa;
  ocall_request_t *pe_request = (ocall_request_t *)pe_request_pa;
  
  if (return_reason == NE_REQUEST_INSPECT)
  { 
    /* todo. if the parameter size is too large, cross page. */

    ocall_request_inspect_t ocall_inspect_req;
    void *ne_inspect_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(ne_request->inspect_request));
    void *pe_inspect_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(pe_request->inspect_request));
    sbi_memcpy(pe_inspect_pa, ne_inspect_pa, sizeof(ocall_request_inspect_t));

    sbi_memcpy((void *)(&ocall_inspect_req), pe_inspect_pa, sizeof(ocall_request_inspect_t));
  }
  else if (return_reason == NE_REQUEST_SHARE_PAGE)
  {

    ocall_request_share_t ocall_share_req;
    void *ne_share_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(ne_request->share_page_request));
    void *pe_share_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(pe_request->share_page_request));
    sbi_memcpy(pe_share_pa, ne_share_pa, sizeof(ocall_request_share_t));
    
    sbi_memcpy((void *)(&ocall_share_req), pe_share_pa, sizeof(ocall_request_share_t));
  }
  else if (return_reason == NE_REQUEST_ACQUIRE_PAGE)
  {

    ocall_request_share_t ocall_share_req;
    void *ne_share_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(ne_request->share_page_request));
    void *pe_share_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(pe_request->share_page_request));
    sbi_memcpy(pe_share_pa, ne_share_pa, sizeof(ocall_request_share_t));
    
    sbi_memcpy((void *)(&ocall_share_req), pe_share_pa, sizeof(ocall_request_share_t));
  }
  else if (return_reason == NE_REQUEST_DEBUG_PRINT)
  {
    return ret;
    sbi_printf("[sm] [swap_from_host_to_enclave] eid [%u]\n", enclave->eid);
    sbi_printf("[sm] _stack_top [%lx], _heap_top [%lx]\n", enclave->_stack_top, enclave->_heap_top);
    struct vm_area_struct* cur_vma = NULL;
    struct pm_area_struct* cur_pma = NULL;
    
    cur_pma = enclave->pma_list;
    while (cur_pma != NULL)
    {
      sbi_printf("[sm] pma [%p], free_mem [%lx], paddr [%lx], size [%lu]\n", 
        (void *)cur_pma, cur_pma->free_mem, cur_pma->paddr, cur_pma->size);
      cur_pma = cur_pma->pm_next;
    }
    cur_vma = enclave->text_vma;
    while (cur_vma != NULL)
    {
      sbi_printf("[sm] text_vma [%p], ->pma [%p], va_start [%lx], va_end [%lx], size [%lu]\n", 
        (void *)cur_vma, cur_vma->pma, cur_vma->va_start, cur_vma->va_end, (cur_vma->va_end - cur_vma->va_start));
      cur_vma = cur_vma->vm_next;  
    }
    
    cur_vma = enclave->stack_vma;
    while (cur_vma != NULL)
    {
      sbi_printf("[sm] stack_vma [%p], ->pma [%p], va_start [%lx], va_end [%lx], size [%lu]\n", 
        (void *)cur_vma, cur_vma->pma, cur_vma->va_start, cur_vma->va_end, (cur_vma->va_end - cur_vma->va_start));
      cur_vma = cur_vma->vm_next;  
    }
    cur_vma = enclave->heap_vma;
    while (cur_vma != NULL)
    {
      sbi_printf("[sm] heap_vma [%p], ->pma [%p], va_start [%lx], va_end [%lx], size [%lu]\n", 
        (void *)cur_vma, cur_vma->pma, cur_vma->va_start, cur_vma->va_end, (cur_vma->va_end - cur_vma->va_start));
      cur_vma = cur_vma->vm_next;  
    }
    cur_vma = enclave->mmap_vma;
    while (cur_vma != NULL)
    {
      sbi_printf("[sm] mmap_vma [%p], ->pma [%p], va_start [%lx], va_end [%lx], size [%lu]\n", 
        (void *)cur_vma, cur_vma->pma, cur_vma->va_start, cur_vma->va_end, (cur_vma->va_end - cur_vma->va_start));
      cur_vma = cur_vma->vm_next;  
    }
  }
out:
  return ret;
}

/**
 * \brief Accept the reason of NE, resume its parent PE.
 * 
 * \param enclave The enclave structure.
 * \param return_reason The reason why Normal Enclave stop/crash (IRQ, Share Page, ...)
 * \param return_value The NE process's return value.
 * 
 * \details The whole function is locked, so don't need to update target enclave state as ATTESTING.
 *          EXIT_ENCLAVE won't enter this function, instead, it will enter sm_exit_enclave().
 * \details return_value is valid/useful if and only if return_reason == RETURN_USER_EXIT_ENCL (0)
 */
uintptr_t privil_resume_after_resume(struct enclave_t *enclave, uintptr_t return_reason, uintptr_t return_value)
{
  uintptr_t ret = 0;
  int return_reason_int = return_reason;
  int return_value_int = return_value;
  ocall_run_param_t run_args;
  struct enclave_t *tgt_enclave = NULL;
  sbi_memcpy(&run_args, (void *)(enclave->kbuffer), sizeof(ocall_run_param_t));

  tgt_enclave = __get_enclave(run_args.run_eid);
  if (!tgt_enclave)
  {
    sbi_bug("M mode: privil_run_after_resume: enclave%d is not valid\n", run_args.run_eid);
    ret = -1UL; goto out;
  }
  if (tgt_enclave->state > FRESH && tgt_enclave->parent_eid != enclave->eid)
  {
    sbi_bug("M mode: privil_run_after_resume: [%d] will returns to an unmatched parent [%d]. Expected: [%ld]", 
                     run_args.run_eid, enclave->eid, tgt_enclave->parent_eid);
    ret = -1UL; goto out;
  }

  void *reason_ptr = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(run_args.reason_ptr));
  if (!reason_ptr)
  {
    ret = -1UL;
    sbi_bug("M mode: privil_attest_after_resume: enclave%d PT can not be accessed!\n", enclave->eid);
  }
  sbi_memcpy(reason_ptr, (void *)(&return_reason_int), sizeof(int));

  void *retval_ptr = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(run_args.retval_ptr));
  if (!retval_ptr)
  {
    ret = -1UL;
    sbi_bug("M mode: privil_attest_after_resume: enclave%d PT can not be accessed!\n", enclave->eid);
  }
  sbi_memcpy(retval_ptr, (void *)(&return_value_int), sizeof(int));


  /* handle Request from Normal Enclave, load its request and write it into PE's running param. */
  uintptr_t ne_request_arg = return_value;
  void *ne_request_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(ne_request_arg));
  void *pe_request_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(run_args.request_arg));
  ocall_request_t *ne_request = (ocall_request_t *)ne_request_pa;
  ocall_request_t *pe_request = (ocall_request_t *)pe_request_pa;
  
  if (return_reason == NE_REQUEST_INSPECT)
  { 
    ocall_request_inspect_t ocall_inspect_req;
    void *ne_inspect_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(ne_request->inspect_request));
    void *pe_inspect_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(pe_request->inspect_request));
    sbi_memcpy(pe_inspect_pa, ne_inspect_pa, sizeof(ocall_request_inspect_t));
    sbi_memcpy((void *)(&ocall_inspect_req), pe_inspect_pa, sizeof(ocall_request_inspect_t));
  }
  else if (return_reason == NE_REQUEST_SHARE_PAGE)
  {
    ocall_request_share_t ocall_share_req;
    void *ne_share_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(ne_request->share_page_request));
    void *pe_share_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(pe_request->share_page_request));
    sbi_memcpy(pe_share_pa, ne_share_pa, sizeof(ocall_request_share_t));
    
    sbi_memcpy((void *)(&ocall_share_req), pe_share_pa, sizeof(ocall_request_share_t));
  }
  else if (return_reason == NE_REQUEST_ACQUIRE_PAGE)
  {
    ocall_request_share_t ocall_share_req;
    void *ne_share_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(ne_request->share_page_request));
    void *pe_share_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(pe_request->share_page_request));
    sbi_memcpy(pe_share_pa, ne_share_pa, sizeof(ocall_request_share_t));
    
    sbi_memcpy((void *)(&ocall_share_req), pe_share_pa, sizeof(ocall_request_share_t));
  }
  else if (return_reason == NE_REQUEST_DEBUG_PRINT)
  {
    return ret;
    sbi_printf("[sm] [swap_from_host_to_enclave] eid [%u]\n", tgt_enclave->eid);
    sbi_printf("[sm] _stack_top [%lx], _heap_top [%lx]\n", tgt_enclave->_stack_top, tgt_enclave->_heap_top);
    struct vm_area_struct* cur_vma = NULL;
    struct pm_area_struct* cur_pma = NULL;
    
    cur_pma = tgt_enclave->pma_list;
    while (cur_pma != NULL)
    {
      sbi_printf("[sm] pma [%p], free_mem [%lx], paddr [%lx], size [%lu]\n", 
        (void *)cur_pma, cur_pma->free_mem, cur_pma->paddr, cur_pma->size);
      cur_pma = cur_pma->pm_next;
    }
    cur_vma = tgt_enclave->text_vma;
    while (cur_vma != NULL)
    {
      sbi_printf("[sm] text_vma [%p], ->pma [%p], va_start [%lx], va_end [%lx], size [%lu]\n", 
        (void *)cur_vma, cur_vma->pma, cur_vma->va_start, cur_vma->va_end, (cur_vma->va_end - cur_vma->va_start));
      cur_vma = cur_vma->vm_next;  
    }
    
    cur_vma = tgt_enclave->stack_vma;
    while (cur_vma != NULL)
    {
      sbi_printf("[sm] stack_vma [%p], ->pma [%p], va_start [%lx], va_end [%lx], size [%lu]\n", 
        (void *)cur_vma, cur_vma->pma, cur_vma->va_start, cur_vma->va_end, (cur_vma->va_end - cur_vma->va_start));
      cur_vma = cur_vma->vm_next;  
    }
    cur_vma = tgt_enclave->heap_vma;
    while (cur_vma != NULL)
    {
      sbi_printf("[sm] heap_vma [%p], ->pma [%p], va_start [%lx], va_end [%lx], size [%lu]\n", 
        (void *)cur_vma, cur_vma->pma, cur_vma->va_start, cur_vma->va_end, (cur_vma->va_end - cur_vma->va_start));
      cur_vma = cur_vma->vm_next;  
    }
    cur_vma = tgt_enclave->mmap_vma;
    while (cur_vma != NULL)
    {
      sbi_printf("[sm] mmap_vma [%p], ->pma [%p], va_start [%lx], va_end [%lx], size [%lu]\n", 
        (void *)cur_vma, cur_vma->pma, cur_vma->va_start, cur_vma->va_end, (cur_vma->va_end - cur_vma->va_start));
      cur_vma = cur_vma->vm_next;  
    }
  }
out:
  return ret;
}

/**
 * \brief Just perform sanity check and return to PE.
 * 
 * \param enclave The enclave structure.
 * \param dump_arg The VA of enclave dump_arg.
 */
uintptr_t privil_destroy_after_resume(struct enclave_t *enclave)
{
  uintptr_t ret = 0;
  return ret;
}

/**
 * \brief Write inspect result to PE.
 * 
 * \param enclave The enclave structure.
 * \param inspect_result The VA of PE, written target.
 * \param inspect_size  The inspect size
 */
uintptr_t privil_inspect_after_resume(struct enclave_t *enclave, uintptr_t inspect_result, uintptr_t inspect_size)
{
  uintptr_t ret = 0;
  unsigned remain_page_size;
  unsigned param_size = inspect_size;
  /* write data buffer back to PE. */
  
  void *inspect_result_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)inspect_result);
  if (!inspect_result_pa)
  {
    ret = -1UL;
    sbi_bug("[sm] [privil_inspect_after_resume] invalid inspect_result\n");
  }

  remain_page_size = PAGE_SIZE - (inspect_result & (PAGE_SIZE-1));
  if (param_size > remain_page_size)
  {
    sbi_memcpy(inspect_result_pa, (void *)(enclave->kbuffer), remain_page_size);
    sbi_memcpy(va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(inspect_result+remain_page_size)),
              (void *)(enclave->kbuffer + remain_page_size),
              param_size - remain_page_size);
  }
  else 
  {
    sbi_memcpy(inspect_result_pa, (void *)(enclave->kbuffer), param_size);  
  }
  /* check on enclave */
  return ret;
}

/**
 * \brief Host use this fucntion to re-enter enclave world.
 * 
 * \param regs The host register context.
 * \param eid Resume enclave id.
 */
uintptr_t resume_from_ocall(uintptr_t* regs, unsigned int eid)
{
  uintptr_t retval = 0;
  uintptr_t ocall_func_id = regs[12];
  struct enclave_t* enclave = NULL;

  acquire_enclave_metadata_lock();

  enclave = __get_real_enclave(eid);
  if(!enclave || enclave->state != OCALLING || enclave->host_ptbr != csr_read(CSR_SATP))
  {
    retval = -1UL;
    goto out;
  }

  switch(ocall_func_id)
  {
    case OCALL_MMAP:
      retval = mmap_after_resume(enclave, regs[13], regs[14]);
      if(retval == -1UL)
        goto out;
      break;
    case OCALL_UNMAP:
      retval = 0;
      break;
    case OCALL_SYS_WRITE:
      retval = enclave->thread_context.prev_state.a0;
      break;
    case OCALL_SBRK:
      retval = sbrk_after_resume(enclave, regs[13], regs[14]);
      if(retval == -1UL)
        goto out;
      break;
    case OCALL_READ_SECT:
      retval = regs[13];
      break;
    case OCALL_WRITE_SECT:
      retval = regs[13];
      break;
    case OCALL_RETURN_RELAY_PAGE:
      retval = return_relay_page_after_resume(enclave, regs[13], regs[14]);
      if(retval == -1UL)
        goto out;
      break;
    case OCALL_SHM_GET:
      retval = shmget_after_resume(enclave, regs[13], regs[14]);
      break;
    case OCALL_SHM_EXTEND_MEMORY:
      retval = shmextend_after_resume(enclave,regs[13]);
      break;
    case OCALL_CREATE_ENCLAVE:
      retval = privil_create_after_resume(enclave, regs[13], regs[14]);
      break;
    case OCALL_ATTEST_ENCLAVE:
      retval = privil_attest_after_resume(enclave, regs[13]);
      break;
    case OCALL_RUN_ENCLAVE:
      retval = privil_run_after_resume(enclave, regs[13], regs[14]);
      break;
    case OCALL_RESUME_ENCLAVE:
      retval = privil_resume_after_resume(enclave, regs[13], regs[14]);
      break;
    case OCALL_DESTROY_ENCLAVE:
      retval = privil_destroy_after_resume(enclave);
      break;
    case OCALL_INSPECT_ENCLAVE:
      retval = privil_inspect_after_resume(enclave, regs[13], regs[14]);
    default:
      retval = 0;
      break;
  }

  if(swap_from_host_to_enclave(regs, enclave) < 0)
  {
    retval = -1UL;
    goto out;
  }
  enclave->state = RUNNING;

out:
  release_enclave_metadata_lock();
  if ((ocall_func_id == OCALL_MMAP) || (ocall_func_id == OCALL_SBRK)) 
    tlb_remote_sfence();
  return retval;
}

/**
 * \brief Host calls this function to destroy an existing enclave.
 * 
 * \param regs The host register context.
 * \param eid Destroyed enclave id.
 */
uintptr_t destroy_enclave(uintptr_t* regs, unsigned int eid)
{
  uintptr_t retval = 0;
  struct enclave_t *enclave = NULL;
  struct enclave_t *parent = NULL;
  uintptr_t dest_hart = 0;
  struct pm_area_struct* pma = NULL;
  int top_caller_id;
  struct enclave_t *top_caller_enclave = NULL;
  unsigned long satp = 0;
  acquire_enclave_metadata_lock();

  enclave = __get_enclave(eid);

  if(check_in_enclave_world() == 0)
    satp = enclave->host_ptbr;
  else
    satp = csr_read(CSR_SATP);

  unsigned long mm_arg_paddr[RELAY_PAGE_NUM];
  unsigned long mm_arg_size[RELAY_PAGE_NUM];
  for(int kk = 0; kk < RELAY_PAGE_NUM; kk++)
  {
    mm_arg_paddr[kk] = enclave->mm_arg_paddr[kk];
    mm_arg_size[kk] = enclave->mm_arg_size[kk];
  }
  if(!enclave || enclave->state < FRESH)
  {
    sbi_bug("M mode: destroy_enclave: enclave%d can not be accessed\n", eid);
    retval = -1UL;
    release_enclave_metadata_lock();
    goto destroy_enclave_out;
  }

  if (enclave->parent_eid != NULL_EID)
  {
    parent = __get_enclave(enclave->parent_eid);
    if (!parent)
    {
      retval = ENCLAVE_ERROR;
      sbi_bug("M mode: cannot access parent enclave [%lu]\n", enclave->parent_eid);
      goto release_and_out;
    }
    if (parent->type != PRIVIL_ENCLAVE || parent->state < FRESH)
    {
      retval = ENCLAVE_ERROR;
      sbi_bug("M mode: illegal parent [%lu]\n", enclave->parent_eid);
      goto release_and_out;
    }

    if (__get_children(enclave->eid, parent->children_metadata_head) == NULL)
    {
      retval = ENCLAVE_ERROR;
      sbi_bug("M mode: children [%u] not existed in parent [%lu]\n", enclave->eid, enclave->parent_eid);
      goto release_and_out;
    }
    
    if (__free_children(enclave->eid, parent->children_metadata_head))
    {
      retval = ENCLAVE_ERROR;
      sbi_bug("M mode: children [%u] free failed [check again]\n", enclave->eid);
      goto release_and_out;
    }

    if (__get_children(enclave->eid, parent->children_metadata_head) != NULL)
    {
      retval = ENCLAVE_ERROR;
      sbi_bug("M mode: children [%u] has existed in parent [%lu] [check again]\n", enclave->eid, enclave->parent_eid);
      goto release_and_out;
    }
  }


  // Enclave is not running, just reclaim the enclave resource and free its metadata
  if(enclave->state != RUNNING)
  {
    if (enclave->type == SERVER_ENCLAVE)
    {
      release_enclave_metadata_lock();
      destroy_server_enclave(regs, eid);
    }
    else
    {
      pma = enclave->pma_list;
      __free_enclave(eid);
      free_enclave_memory(pma);
      free_all_relay_page(mm_arg_paddr, mm_arg_size);
      release_enclave_metadata_lock();
    }
  }
  // Enclave is running, reclaim the enclave resource and swap CPU state to the normal mode.
  else
  {
    //cpus' state will be protected by enclave_metadata_lock
    for(int i = 0; i < MAX_HARTS; ++i)
    {
      if(cpus[i].in_enclave && cpus[i].eid == eid)
        dest_hart = i;
    }
    // If enclave is running in the current hart
    if (dest_hart == csr_read(CSR_MHARTID))
    {
      NEED_DESTORY_ENCLAVE[dest_hart] = 1;
      if(enclave->type == SERVER_ENCLAVE)
      {
        top_caller_id = enclave->top_caller_eid;
        top_caller_enclave = __get_enclave(top_caller_id);
        // Return the runncing context to the top caller enclave
        __enclave_return(regs, enclave, top_caller_enclave, top_caller_enclave);
        enclave->state = RUNNABLE;
        top_caller_enclave->state = RUNNING;
        eid = top_caller_id;
      }
      release_enclave_metadata_lock();
      // Destroy the top caller / current enclave
      ipi_destroy_enclave(regs, satp, eid);
    }
    else
    {
      if(enclave->type == SERVER_ENCLAVE)
      {
        sbi_bug("M mode: destroy_enclave: destroy a server enclane%d which is not running\n", eid);
        retval = -1UL;
        release_enclave_metadata_lock();
        goto destroy_enclave_out;
      }
      NEED_DESTORY_ENCLAVE[dest_hart] = 1;
      release_enclave_metadata_lock();
      set_ipi_destroy_enclave_and_sync(dest_hart, satp, eid);
    }
  }

release_and_out:
  release_enclave_metadata_lock();
destroy_enclave_out:

  return retval;
}

/**
 * \brief Host calls this function to stop an existing enclave.
 * 
 * \param regs The host register context.
 * \param eid Stopped enclave id.
 */
uintptr_t stop_enclave(uintptr_t* regs, unsigned int eid)
{
  uintptr_t retval = 0, dest_hart = 0;
  struct enclave_t *enclave = NULL;
  if(check_in_enclave_world() == 0)
  {
    sbi_bug("M mode: stop_enclave: should not be called by enclave itself\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  enclave = __get_enclave(eid);
  if(!enclave || enclave->state <= FRESH || enclave->state == ATTESTING || enclave->state == OCALLING || enclave->host_ptbr != csr_read(CSR_SATP) || enclave->type == SERVER_ENCLAVE)
  {
    sbi_bug("M mode: stop_enclave: enclave%d can not be accessed!\n", eid);
    retval = -1UL;
    goto stop_enclave_out;
  }

  //printm("M mode: stop_enclave: now we stop enclave%d\n", eid);
  if(enclave->state != RUNNING)
  {
    //printm("enclave %d is not running, no need to send ipi\n", eid);
    enclave->state = STOPPED;
    release_enclave_metadata_lock();
  }
  else
  {
    //cpus' state will be protected by enclave_metadata_lock
    for(int i = 0; i < MAX_HARTS; ++i)
    {
      if(cpus[i].in_enclave && cpus[i].eid == eid)
        dest_hart = i;
    }
    if (dest_hart == csr_read(CSR_MHARTID))
    {
      NEED_STOP_ENCLAVE[dest_hart] = 1;
      release_enclave_metadata_lock();
      ipi_stop_enclave(regs, csr_read(CSR_SATP), eid);
    }
    else
    {
      NEED_STOP_ENCLAVE[dest_hart] = 1;
      release_enclave_metadata_lock();
      set_ipi_stop_enclave_and_sync(dest_hart, csr_read(CSR_SATP), eid);
    }
  }

stop_enclave_out:
  return retval;
}

/**************************************************************/
/*                   called by Privileged Enclave             */
/**************************************************************/
/**
 * \brief Host calls this function to inspect a running children enclave.
 * 
 * \param tgt_eid The inspectee eid. (slab-layer)
 * \param src_eid The inspector eid. (slab-layer)
 * \param dump_context 0 means do inspection on memory region, otherwise dump register state.
 * \param inspect_addr The start VA address of inspectee region
 * \param inspect_size The size of inspectee region (<= PAGE SIZE, normally 4kB)
 */
uintptr_t inspect_enclave(uintptr_t tgt_eid, uintptr_t src_eid, uintptr_t dump_context, uintptr_t inspect_addr, uintptr_t inspect_size)
{
  uintptr_t retval = 0;
  unsigned remain_page_size;
  struct enclave_t *tgt_enclave = NULL;
  struct enclave_t *src_enclave = NULL;
  struct vm_area_struct *heap_vma = NULL;
  struct vm_area_struct *mmap_vma = NULL;
  acquire_enclave_metadata_lock();

  tgt_enclave = __get_enclave(tgt_eid);
  if (!tgt_enclave || tgt_enclave->state < FRESH || 
       tgt_enclave->parent_eid != src_eid || 
       tgt_enclave->type != NORMAL_ENCLAVE)
  {
    sbi_bug("M mode: inspect_enclave: target enclave%lu can not be accessed\n", tgt_eid);
    retval = -1UL;
    goto inspect_enclave_out;
  }

  /* give a stronger check in future */
  src_enclave = __get_enclave(src_eid);
  if (!src_enclave || src_enclave->state != OCALLING || 
       src_enclave->parent_eid != NULL_EID || 
       src_enclave->type != PRIVIL_ENCLAVE)
  {
    sbi_bug("M mode: inspect_enclave: source enclave%lu can not be accessed\n", src_eid);
    retval = -1UL;
    goto inspect_enclave_out;
  }


  if (dump_context == INSPECT_REGS)
  {
    /* dump the NE's register context. */
    struct thread_state_t tgt_context = tgt_enclave->thread_context;
    copy_to_host((void *)(src_enclave->kbuffer), (void *)(&tgt_context), sizeof(struct thread_state_t));
  }
  else if (dump_context == INSPECT_VMA)
  {
    enclave_mem_dump_t enclave_mem_dump;
    /* fixme. text_vma can be ignored. */
    enclave_mem_dump.text_vma.va_start = tgt_enclave->text_vma->va_start;
    enclave_mem_dump.text_vma.va_end = tgt_enclave->text_vma->va_end;
    enclave_mem_dump.stack_vma.va_start = tgt_enclave->stack_vma->va_start;
    enclave_mem_dump.stack_vma.va_end = tgt_enclave->stack_vma->va_end;
    unsigned i = 0;
    heap_vma = tgt_enclave->heap_vma;
    while (i < DEFAULT_HEAP_VMA_MAX)
    {
      if (!heap_vma)
      { 
        enclave_mem_dump.heap_sz = i;
        break;
      }
      enclave_mem_dump.heap_vma[i].va_start = heap_vma->va_start;
      enclave_mem_dump.heap_vma[i].va_end = heap_vma->va_end;
      heap_vma = heap_vma->vm_next;
      i++;
    }
    if (heap_vma)
    {
      sbi_bug("M mode: inspect_enclave: heap entry exceeds maximal entry number!\n");
      retval = -1UL;
      goto inspect_enclave_out;
    }

    i = 0;
    mmap_vma = tgt_enclave->mmap_vma;
    while (i < DEFAULT_MMAP_VMA_MAX)
    {
      if (!mmap_vma)
      {
        enclave_mem_dump.mmap_sz = i;
        break;
      }
      enclave_mem_dump.mmap_vma[i].va_start = mmap_vma->va_start;
      enclave_mem_dump.mmap_vma[i].va_end = mmap_vma->va_end;
      mmap_vma = mmap_vma->vm_next;
      i++;
    }
    if (mmap_vma)
    {
      sbi_bug("M mode: inspect_enclave: mmap entry exceeds maximal entry number!\n");
      retval = -1UL;
      goto inspect_enclave_out;
    }
    copy_to_host((void *)(src_enclave->kbuffer), (void *)(&enclave_mem_dump), sizeof(enclave_mem_dump_t));
  }
  else 
  {
    if (inspect_size > PAGE_SIZE)
    {
      sbi_bug("M mode: inspect_enclave: inspect_size [%lu] is too large.\n", inspect_size);
      retval = -1UL;
      goto inspect_enclave_out;
    }
    /* do inspection on NE memory region */
    void *inspect_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)inspect_addr);
    if (!inspect_pa)
    {
      sbi_bug("M mode: inspect_enclave: inspect_pa [%p] can not be accessed\n", inspect_pa);
      retval = -1UL;
      goto inspect_enclave_out;
    }
    remain_page_size = PAGE_SIZE - (inspect_addr & (PAGE_SIZE-1));
    if (inspect_size > remain_page_size)
    {
      void *inspect_pa_next = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(inspect_addr+remain_page_size));
      if (!inspect_pa_next)
      {
        sbi_bug("M mode: inspect_enclave: inspect_pa_next [%p] can not be accessed\n", inspect_pa_next);
        retval = -1UL;
        goto inspect_enclave_out;
      }
      copy_to_host((void *)(src_enclave->kbuffer), inspect_pa, remain_page_size);
      copy_to_host((void *)(src_enclave->kbuffer + remain_page_size), inspect_pa_next, inspect_size - remain_page_size);
    }
    else 
    {
      copy_to_host((void *)(src_enclave->kbuffer), inspect_pa, inspect_size);
    }
  }

inspect_enclave_out:
  release_enclave_metadata_lock();
  return retval;
}

/**
 * \brief Host calls this function to respond a NE request.
 * 
 * \param tgt_eid The NE eid. (slab-layer)
 * \param src_eid The PE eid. (slab-layer)
 * \param response_arg The start VA address of PE's response arg.
 */
uintptr_t response_enclave(uintptr_t tgt_eid, uintptr_t src_eid, uintptr_t response_arg)
{
  uintptr_t retval = 0;
  uintptr_t src_ptr, tgt_ptr;
  unsigned share_size;
  unsigned remain_page_size;
  struct enclave_t *tgt_enclave = NULL;
  struct enclave_t *src_enclave = NULL;
  acquire_enclave_metadata_lock();

  tgt_enclave = __get_enclave(tgt_eid);
  if (!tgt_enclave || tgt_enclave->state < FRESH || 
       tgt_enclave->parent_eid != src_eid || 
       tgt_enclave->type != NORMAL_ENCLAVE)
  {
    sbi_bug("M mode: response_enclave: target enclave%lu can not be accessed\n", tgt_eid);
    retval = -1UL;
    goto response_enclave_out;
  }
  src_enclave = __get_enclave(src_eid);
  if (!src_enclave || src_enclave->state != OCALLING || 
       src_enclave->parent_eid != NULL_EID || 
       src_enclave->type != PRIVIL_ENCLAVE)
  {
    sbi_bug("M mode: response_enclave: source enclave%lu can not be accessed\n", src_eid);
    retval = -1UL;
    goto response_enclave_out;
  }
  /* lazy -> risky */
  void *response_arg_pa = va_to_pa((uintptr_t *)(src_enclave->root_page_table), (void *)response_arg);
  if (!response_arg_pa)
  {
    sbi_bug("M mode: response_enclave: response_arg_pa [%p] can not be accessed\n", response_arg_pa);
    retval = -1UL;
    goto response_enclave_out;
  }
  ocall_response_t *ocall_response_local = (ocall_response_t *)(response_arg_pa);
  if (ocall_response_local->request == NE_REQUEST_ACQUIRE_PAGE)
  {
    void *share_response_pa = va_to_pa((uintptr_t *)(src_enclave->root_page_table), 
                                       (void *)(ocall_response_local->share_page_response));
    if (!share_response_pa)
    {
      sbi_bug("M mode: response_enclave: share_response_pa [%p] can not be accessed\n", share_response_pa);
      retval = -1UL;
      goto response_enclave_out;
    }
    ocall_response_share_t *share_response_local = (ocall_response_share_t *)(share_response_pa);
    
    share_size = share_response_local->share_size;
    /* first we copy to tgt_enclave kbuffer */
    src_ptr = share_response_local->src_ptr;
    void *pe_content_pa = va_to_pa((uintptr_t *)(src_enclave->root_page_table), (void *)(src_ptr));
    if (!pe_content_pa)
    {
      sbi_bug("M mode: response_enclave: pe_content_pa [%p] can not be accessed\n", pe_content_pa);
      retval = -1UL;
      goto response_enclave_out;
    }
    remain_page_size = PAGE_SIZE - (src_ptr & (PAGE_SIZE-1));
    if (share_size > remain_page_size)
    {
      copy_to_host((void *)(tgt_enclave->kbuffer), pe_content_pa, remain_page_size);
      copy_to_host((void *)(tgt_enclave->kbuffer+remain_page_size), 
                   va_to_pa((uintptr_t *)(src_enclave->root_page_table), (void *)(src_ptr+remain_page_size)),
                   share_size - remain_page_size);
    }
    else 
    {
      copy_to_host((void *)(tgt_enclave->kbuffer), pe_content_pa, share_size);
    }

    /* then we copy content back to NE destination */
    tgt_ptr = share_response_local->dest_ptr;
    void *ne_content_pa = va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(tgt_ptr));
    if (!ne_content_pa)
    {
      sbi_bug("M mode: response_enclave: ne_content_pa [%p] can not be accessed\n", ne_content_pa);
      retval = -1UL;
      goto response_enclave_out;
    }
    remain_page_size = PAGE_SIZE - (tgt_ptr & (PAGE_SIZE-1));
    // sbi_printf("[sm] [response_enclave] remain_page_size: [%lu]\n", remain_page_size);
    if (share_size > remain_page_size)
    {
      sbi_memcpy(ne_content_pa, (void *)(tgt_enclave->kbuffer), remain_page_size);
      sbi_memcpy(va_to_pa((uintptr_t *)(tgt_enclave->root_page_table), (void *)(tgt_ptr+remain_page_size)),
                 (void *)(tgt_enclave->kbuffer + remain_page_size), 
                 share_size - remain_page_size);
    }
    else 
    {
      sbi_memcpy(ne_content_pa, (void *)(tgt_enclave->kbuffer), share_size);
    }
  } 
  else 
  {
    /* do extension in future. */
  }

response_enclave_out:
  release_enclave_metadata_lock();
  return retval;
}

/**************************************************************/
/*                   called by enclave                        */
/**************************************************************/
/**
 * \brief Get the enclave id.
 */
uintptr_t get_enclave_id(uintptr_t* regs)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL;
  int eid = 0; 
  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: get_enclave_id: CPU is not in the enclave mode\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
  {
    ret = -1UL;
    sbi_bug("M mode: get_enclave_id: enclave%d can not be accessed!\n", eid);
    goto out;
  }

  ret = eid;

out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief Get enclave attestation report, called by enclave.
 *
 * \param report The attestation report address in enclave.
 * \param nonce The attestation nonce
 */
uintptr_t get_enclave_attest_report(uintptr_t *report, uintptr_t nonce)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL;
  int eid = 0; 
  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: get_enclave_attest_report: CPU is not in the enclave mode\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if(!enclave|| check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
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

  hash_enclave(enclave, (void*)(m_report.enclave.hash), nonce);
  sign_enclave((void*)(m_report.enclave.signature), (void*)(m_report.enclave.hash));
  m_report.enclave.nonce = nonce;

  // Copy attestation report to enclave
  sbi_memcpy(u_report, &m_report, sizeof(struct report_t));


out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief Derive enclave specific key.
 *
 * \param key_type The key type.
 * \param key The received key pointer.
 * \param key_size The received key size.
 */
uintptr_t derive_key(uintptr_t key_type, uintptr_t *key, uintptr_t key_size)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL;
  int eid = 0; 
  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: derive_key: CPU is not in the enclave mode\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if(!enclave|| check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
  {
    ret = -1UL;
    sbi_bug("M mode: derive_key: enclave%d can not be accessed!\n", eid);
    goto out;
  }

  // Get the physical address of the attestaion report
  char* u_key = va_to_pa((uintptr_t*)(enclave->root_page_table), (void*)key);
  if(!u_key)
  {
    sbi_bug("M mode: derive_key: key pointer is invalid \n");
    ret = -1UL;
    goto out;
  }

  // char m_key[KEY_SIZE_BYTES];

  if (m_derive_key((int)key_type, enclave->hash, (int)key_size, u_key) != 0)
  {
    sbi_bug("M mode: derive_key: derive key from the root key is failed\n");
    ret = -1;
  }
  
out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief Exit from the enclave.
 * 
 * \param regs The host register context.
 * \param enclave_retval Enclave return value.
 */
uintptr_t exit_enclave(uintptr_t* regs, unsigned long enclave_retval)
{
  struct enclave_t *enclave = NULL;
  struct enclave_t *parent = NULL;
  int eid = 0;
  uintptr_t ret = 0;
  struct pm_area_struct *pma = NULL;
  int need_free_enclave_memory = 0;
  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: exit_enclave: cpu is not in enclave world now\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave) != 0 || enclave->type == SERVER_ENCLAVE)
  {
    sbi_bug("M mode: exit_enclave: enclave%d can not be accessed!\n", eid);
    ret = -1UL;
    goto exit_enclave_out;
  }

  //copy enclave retval
  copy_dword_to_host((uintptr_t*)enclave->retval, enclave_retval);

  swap_from_enclave_to_host(regs, enclave);

  /* add our children metadata operations here. */
  if (enclave->parent_eid != NULL_EID)
  {
    parent = __get_enclave(enclave->parent_eid);
    if (!parent)
    {
      ret = ENCLAVE_ERROR;
      sbi_bug("M mode: cannot access parent enclave [%lu]\n", enclave->parent_eid);
      goto exit_enclave_out;
    }
    if (parent->type != PRIVIL_ENCLAVE || parent->state < FRESH)
    {
      ret = ENCLAVE_ERROR;
      sbi_bug("M mode: illegal parent [%lu]\n", enclave->parent_eid);
      goto exit_enclave_out;
    }
    if (__get_children(enclave->eid, parent->children_metadata_head) == NULL)
    {
      ret = ENCLAVE_ERROR;
      sbi_bug("M mode: children [%u] not existed in parent [%lu]\n", enclave->eid, enclave->parent_eid);
      goto exit_enclave_out;
    }
    if (__free_children(enclave->eid, parent->children_metadata_head))
    {
      ret = ENCLAVE_ERROR;
      sbi_bug("M mode: children [%u] free failed [check again]\n", enclave->eid);
      goto exit_enclave_out;
    }
    if (__get_children(enclave->eid, parent->children_metadata_head) != NULL)
    {
      ret = ENCLAVE_ERROR;
      sbi_bug("M mode: children [%u] has existed in parent [%lu] [check again]\n", enclave->eid, enclave->parent_eid);
      goto exit_enclave_out;
    }

  }

  pma = enclave->pma_list;
  need_free_enclave_memory = 1;
  unsigned long mm_arg_paddr[RELAY_PAGE_NUM];
  unsigned long mm_arg_size[RELAY_PAGE_NUM];
  for(int kk = 0; kk < RELAY_PAGE_NUM; kk++)
  {
    mm_arg_paddr[kk] = enclave->mm_arg_paddr[kk];
    mm_arg_size[kk] = enclave->mm_arg_size[kk];
  }
  __free_enclave(eid);

exit_enclave_out:
  // __list_relay_page_by_name();

  if(need_free_enclave_memory)
  {
    free_enclave_memory(pma);
    free_all_relay_page(mm_arg_paddr, mm_arg_size);
  }
  // __list_relay_page_by_name();
  release_enclave_metadata_lock();
  return ret;
}


/**
 * \brief Enclave needs to map a new mmap region, ocall to host to handle it.
 * 
 * \param regs The enclave register context.
 * \param vaddr Mmap virtual address.
 * \param suze Mmap virtual memory size.
 */
uintptr_t enclave_mmap(uintptr_t* regs, uintptr_t vaddr, uintptr_t size)
{
  uintptr_t ret = 0;
  int eid = get_curr_enclave_id();
  struct enclave_t* enclave = NULL;
  if(check_in_enclave_world() < 0)
    return SYS_NULL;
  if(vaddr)
  {
    if(vaddr & (RISCV_PGSIZE-1) || size < RISCV_PGSIZE || size & (RISCV_PGSIZE-1))
      return SYS_NULL;
  }

  acquire_enclave_metadata_lock();

  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
  {
    ret = SYS_NULL;
    goto out;
  }

  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_MMAP);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, size + RISCV_PGSIZE);

  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;

out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief Enclave needs to unmap a mmap region, ocall to host to handle it.
 * 
 * \param regs The enclave register context.
 * \param vaddr Unmap virtual address.
 * \param suze Unmap virtual memory size.
 */
uintptr_t enclave_unmap(uintptr_t* regs, uintptr_t vaddr, uintptr_t size)
{
  uintptr_t ret = 0;
  int eid = get_curr_enclave_id();
  struct enclave_t* enclave = NULL;
  struct vm_area_struct *vma = NULL;
  struct pm_area_struct *pma = NULL;
  int need_free_secure_memory = 0;
  if(check_in_enclave_world() < 0)
    return -1;

  acquire_enclave_metadata_lock();

  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
  {
    ret = -1UL;
    goto out;
  }

  vma = find_vma(enclave->mmap_vma, vaddr, size);
  if(!vma)
  {
    ret = -1UL;
    goto out;
  }
  pma = vma->pma;
  delete_vma(&(enclave->mmap_vma), vma);
  delete_pma(&(enclave->pma_list), pma);
  vma->vm_next = NULL;
  pma->pm_next = NULL;
  unmap((uintptr_t*)(enclave->root_page_table), vma->va_start, vma->va_end - vma->va_start);
  need_free_secure_memory = 1;

  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_UNMAP);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, pma->paddr);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, pma->size);

  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;

out:
  release_enclave_metadata_lock();
  if(need_free_secure_memory)
  {
    free_enclave_memory(pma);
  }
  return ret;
}

/**
 * \brief Enclave calls sbrk() during the runtime to expand heap, ocall to host to handle it.
 * 
 * \param regs The enclave register context.
 * \param size Stack augment memory size.
 */
uintptr_t enclave_sbrk(uintptr_t* regs, intptr_t size)
{
  uintptr_t ret = 0;
  uintptr_t abs_size = 0;
  int eid = get_curr_enclave_id();
  struct enclave_t* enclave = NULL;
  struct pm_area_struct *pma = NULL;
  struct vm_area_struct *vma = NULL;
  if(check_in_enclave_world() < 0)
    return -1;
  if(size < 0)
  {
    abs_size = 0 - size;
  }
  else
  {
    abs_size = size;
  }
  if(abs_size & (RISCV_PGSIZE-1))
    return -1;

  acquire_enclave_metadata_lock();

  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
  {
    ret = -1UL;
    goto out;
  }

  if(size == 0)
  {
    ret = enclave->_heap_top;
    goto out;
  }
  if(size < 0)
  {
    uintptr_t dest_va = enclave->_heap_top - abs_size;
    vma = enclave->heap_vma;
    while(vma && vma->va_start >= dest_va)
    {
      struct pm_area_struct *cur_pma = vma->pma;
      delete_pma(&(enclave->pma_list), cur_pma);
      cur_pma->pm_next = pma;
      pma = cur_pma;
      unmap((uintptr_t*)(enclave->root_page_table), vma->va_start, vma->va_end - vma->va_start);
      enclave->heap_vma = vma->vm_next;
      vma = vma->vm_next;
    }
    if(enclave->heap_vma)
      enclave->_heap_top = enclave->heap_vma->va_end;
    else
      enclave->_heap_top = ENCLAVE_DEFAULT_HEAP_BASE;
  }
  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_SBRK);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, (uintptr_t)pma);
  if(size > 0)
    copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, size + RISCV_PGSIZE);
  else
    copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, size);

  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;

out:
  release_enclave_metadata_lock();
  if(pma)
  {
    free_enclave_memory(pma);
  }
  return ret;
}

/**
 * \brief Enclave calls print() during the runtime, ocall to host to handle it.
 * 
 * \param regs The enclave register context.
 */
uintptr_t enclave_sys_write(uintptr_t* regs)
{
  uintptr_t ret = 0;
  int eid = get_curr_enclave_id();
  struct enclave_t* enclave = NULL;
  if(check_in_enclave_world() < 0) 
  {
    sbi_bug("M mode: %s check enclave world is failed\n", __func__);
    return -1;
  }
  acquire_enclave_metadata_lock();

  enclave = __get_enclave(eid);

  release_enclave_metadata_lock();

  if(!enclave || check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
  {
    ret = -1UL;
    sbi_bug("M mode: %s check enclave authentication is failed\n", __func__);
    goto out;
  }
  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_SYS_WRITE);

  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;
out:
  return ret;
}

/**
 * \brief Call the server enclave, and transfer the relay page ownership.
 * 
 * \param regs The enclave register context.
 * \param callee_eid The callee enclave id.
 * \param arg The passing arguments.
 */
uintptr_t call_enclave(uintptr_t* regs, unsigned int callee_eid, uintptr_t arg)
{
  struct enclave_t* top_caller_enclave = NULL;
  struct enclave_t* caller_enclave = NULL;
  struct enclave_t* callee_enclave = NULL;
  struct vm_area_struct* vma = NULL;
  struct pm_area_struct* pma = NULL;
  uintptr_t retval = 0;
  int caller_eid = get_curr_enclave_id();
  if(check_in_enclave_world() < 0)
    return -1;

  acquire_enclave_metadata_lock();
  caller_enclave = __get_enclave(caller_eid);
  if(!caller_enclave || caller_enclave->state != RUNNING || check_enclave_authentication(caller_enclave) != 0)
  {
    sbi_bug("M mode: call_enclave: enclave%d can not execute call_enclave!\n", caller_eid);
    retval = -1UL;
    goto out;
  }
  if(caller_enclave->caller_eid != -1)
    top_caller_enclave = __get_enclave(caller_enclave->top_caller_eid);
  else
    top_caller_enclave = caller_enclave;
  if(!top_caller_enclave)
  {
    sbi_bug("M mode: call_enclave: top_caller_enclave%d can not execute call_enclave!\n", caller_enclave->top_caller_eid);
    retval = -1UL;
    goto out;
  }
  callee_enclave = __get_enclave(callee_eid);
  if(!callee_enclave || callee_enclave->type != SERVER_ENCLAVE)
  {
    sbi_bug("M mode: call_enclave: enclave%d can not be accessed!\n", callee_eid);
    sbi_bug("M mode: call_enclave: callee_enclave %lx, type %d state %d\n", (unsigned long) callee_enclave, callee_enclave->type, callee_enclave->state);
    retval = -1UL;
    goto out;
  }

  if(callee_enclave->caller_eid != -1 || callee_enclave->state != RUNNABLE)
  {
      retval = -ESERVERBUSY;
      goto out;
  }
  struct call_enclave_arg_t call_arg;
  struct call_enclave_arg_t* call_arg0 = va_to_pa((uintptr_t*)(caller_enclave->root_page_table), (void*)arg);
  if(!call_arg0)
  {
    sbi_bug("M mode: call_enclave: call_arg0 is not existed \n");
    retval = -1UL;
    goto out;
  }
  sbi_memcpy(&call_arg, call_arg0, sizeof(struct call_enclave_arg_t));
  if(call_arg.req_vaddr != 0)
  {
    if(call_arg.req_vaddr & (RISCV_PGSIZE-1) || call_arg.req_size < RISCV_PGSIZE || call_arg.req_size & (RISCV_PGSIZE-1))
    {
      sbi_bug("M mode: call_enclave: vaddr and size is not align \n");
      retval = -1UL;
      goto out;
    }

    if(call_arg.req_vaddr == ENCLAVE_DEFAULT_MM_ARG_BASE)
    {
      callee_enclave->mm_arg_paddr[0] = caller_enclave->mm_arg_paddr[0];
      callee_enclave->mm_arg_size[0] = caller_enclave->mm_arg_size[0];
      caller_enclave->mm_arg_paddr[0] = 0;
      caller_enclave->mm_arg_paddr[0] = 0;
      unmap((uintptr_t*)(caller_enclave->root_page_table), call_arg.req_vaddr, call_arg.req_size);
      mmap((uintptr_t*)(callee_enclave->root_page_table), &(callee_enclave->free_pages), ENCLAVE_DEFAULT_MM_ARG_BASE, callee_enclave->mm_arg_paddr[0], call_arg.req_size);
    }
    else
    {
      //Unmap for caller enclave
      vma = find_vma(caller_enclave->mmap_vma, call_arg.req_vaddr, call_arg.req_size);
      if(!vma)
      {
        sbi_bug("M mode: call_enclave:vma is not existed \n");
        retval = -1UL;
        goto out;
      }
      pma = vma->pma;
      delete_vma(&(caller_enclave->mmap_vma), vma);
      delete_pma(&(caller_enclave->pma_list), pma);
      vma->vm_next = NULL;
      pma->pm_next = NULL;
      unmap((uintptr_t*)(caller_enclave->root_page_table), vma->va_start, vma->va_end - vma->va_start);
      //Map for callee enclave
      if(insert_vma(&(callee_enclave->mmap_vma), vma, ENCLAVE_DEFAULT_MMAP_BASE) < 0)
      {
        vma->va_end = callee_enclave->mmap_vma->va_start;
        vma->va_start = vma->va_end - (pma->size - RISCV_PGSIZE);
        vma->vm_next = callee_enclave->mmap_vma;
        callee_enclave->mmap_vma = vma;
      }
      insert_pma(&(callee_enclave->pma_list), pma);
      mmap((uintptr_t*)(callee_enclave->root_page_table), &(callee_enclave->free_pages), vma->va_start, pma->paddr + RISCV_PGSIZE, pma->size - RISCV_PGSIZE);
    }
  }
  if(__enclave_call(regs, top_caller_enclave, caller_enclave, callee_enclave) < 0)
  {
    sbi_bug("M mode: call_enclave: enclave can not be run\n");
    retval = -1UL;
    goto out;
  }
  //set return address to enclave
  csr_write(CSR_MEPC, (uintptr_t)(callee_enclave->entry_point));

  //enable timer interrupt
  csr_read_set(CSR_MIE, MIP_MTIP);
  csr_read_set(CSR_MIE, MIP_MSIP);

  //set default stack
  regs[2] = ENCLAVE_DEFAULT_STACK_BASE;

  //map kbuffer
  mmap((uintptr_t*)(callee_enclave->root_page_table), &(callee_enclave->free_pages), ENCLAVE_DEFAULT_KBUFFER, top_caller_enclave->kbuffer, top_caller_enclave->kbuffer_size);
  //pass parameters
  
  regs[10] = call_arg.req_arg;
  if(call_arg.req_vaddr == ENCLAVE_DEFAULT_MM_ARG_BASE)
    regs[11] = ENCLAVE_DEFAULT_MM_ARG_BASE;
  else if(call_arg.req_vaddr)
    regs[11] = vma->va_start;
  else
    regs[11] = 0;
  regs[12] = call_arg.req_size;
  if(callee_enclave->shm_paddr){
    regs[13] = ENCLAVE_DEFAULT_SHM_BASE;
  }
  else{
    regs[13] = 0;
  }
  regs[14] = callee_enclave->shm_size;
  retval = call_arg.req_arg;

  callee_enclave->state = RUNNING;
  caller_enclave->state = RUNNABLE;
out:
  release_enclave_metadata_lock();
  return retval;
}

/**
 * \brief Server enclave return, and transfer the relay page ownership.
 * 
 * \param regs The enclave register context.
 * \param arg The return arguments.
 */
uintptr_t enclave_return(uintptr_t* regs, uintptr_t arg)
{
  struct enclave_t *enclave = NULL;
  struct enclave_t *caller_enclave = NULL;
  struct enclave_t *top_caller_enclave = NULL;
  int eid = 0;
  uintptr_t ret = 0;
  struct vm_area_struct* vma = NULL;
  struct pm_area_struct *pma = NULL;

  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: enclave_return: cpu is not in enclave world now\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave) != 0 || enclave->type != SERVER_ENCLAVE)
  {
    sbi_bug("M mode: enclave_return: enclave%d can not return!\n", eid);
    ret = -1UL;
    goto out;
  }
  struct call_enclave_arg_t ret_arg;
  struct call_enclave_arg_t* ret_arg0 = va_to_pa((uintptr_t*)(enclave->root_page_table), (void*)arg);
  if(!ret_arg0)
  {
    sbi_bug("M mode: enclave_return: ret_arg0 is invalid \n");
    ret = -1UL;
    goto out;
  }
  sbi_memcpy(&ret_arg, ret_arg0, sizeof(struct call_enclave_arg_t));

  caller_enclave = __get_enclave(enclave->caller_eid);
  top_caller_enclave = __get_enclave(enclave->top_caller_eid);
  __enclave_return(regs, enclave, caller_enclave, top_caller_enclave);
  unmap((uintptr_t*)(enclave->root_page_table), ENCLAVE_DEFAULT_KBUFFER, top_caller_enclave->kbuffer_size);

  //restore caller_enclave's req arg
  //there is no need to check call_arg's validity again as it is already checked when executing call_enclave()
  struct call_enclave_arg_t *call_arg = va_to_pa((uintptr_t*)(caller_enclave->root_page_table), (void*)(regs[11]));

  //restore req_vaddr
  if(!call_arg->req_vaddr || !ret_arg.req_vaddr || ret_arg.req_vaddr & (RISCV_PGSIZE-1)
      || ret_arg.req_size < call_arg->req_size || ret_arg.req_size & (RISCV_PGSIZE-1))
  {
    call_arg->req_vaddr = 0;
    sbi_printf("M MODE: enclave return: the ret argument is in-consistent with caller argument\n");
    sbi_bug("M MODE: enclave return: call_arg->req_vaddr %lx call_arg->req_size %lx ret_arg->req_vaddr %lx ret_arg->size %lx\n", call_arg->req_vaddr, call_arg->req_size, ret_arg.req_vaddr, ret_arg.req_size);
    goto restore_resp_addr;
  }
  //Remap for caller enclave
  if(call_arg->req_vaddr == ENCLAVE_DEFAULT_MM_ARG_BASE)
  {
    caller_enclave->mm_arg_paddr[0] = enclave->mm_arg_paddr[0];
    caller_enclave->mm_arg_size[0] = enclave->mm_arg_size[0];
    enclave->mm_arg_paddr[0] = 0;
    enclave->mm_arg_paddr[0] = 0;
    unmap((uintptr_t*)(enclave->root_page_table), call_arg->req_vaddr, call_arg->req_size);
    mmap((uintptr_t*)(caller_enclave->root_page_table), &(caller_enclave->free_pages), call_arg->req_vaddr, caller_enclave->mm_arg_paddr[0], call_arg->req_size);
  }
  else
  {
    vma = find_vma(enclave->mmap_vma, ret_arg.req_vaddr, ret_arg.req_size);
    if(!vma)
    {
      //enclave return even when the shared mem return failed
      call_arg->req_vaddr = 0;
      sbi_bug("M MODE: enclave return: can not find the corresponding vma for callee enclave\n");
      goto restore_resp_addr;
    }
    pma = vma->pma;
    delete_vma(&(enclave->mmap_vma), vma);
    delete_pma(&(enclave->pma_list), pma);
    unmap((uintptr_t*)(enclave->root_page_table), vma->va_start, vma->va_end - vma->va_start);
    vma->va_start = call_arg->req_vaddr;
    vma->va_end = vma->va_start + pma->size - RISCV_PGSIZE;
    vma->vm_next = NULL;
    pma->pm_next = NULL;
    if(insert_vma(&(caller_enclave->mmap_vma), vma, ENCLAVE_DEFAULT_MMAP_BASE) < 0)
    {
      vma->va_end = caller_enclave->mmap_vma->va_start;
      vma->va_start = vma->va_end - (pma->size - RISCV_PGSIZE);
      vma->vm_next = caller_enclave->mmap_vma;
      caller_enclave->mmap_vma = vma;
    }
    insert_pma(&(caller_enclave->pma_list), pma);
    mmap((uintptr_t*)(caller_enclave->root_page_table), &(caller_enclave->free_pages), vma->va_start, pma->paddr + RISCV_PGSIZE, pma->size - RISCV_PGSIZE);
    call_arg->req_vaddr = vma->va_start;
  }

restore_resp_addr:
  if(!ret_arg.resp_vaddr || ret_arg.resp_vaddr & (RISCV_PGSIZE-1)
      || ret_arg.resp_size < RISCV_PGSIZE || ret_arg.resp_size & (RISCV_PGSIZE-1))
  {
    call_arg->resp_vaddr = 0;
    call_arg->resp_size = 0;
    goto restore_return_val;
  }
  vma = find_vma(enclave->mmap_vma, ret_arg.resp_vaddr, ret_arg.resp_size);
  if(!vma)
  {
    //enclave return even when the shared mem return failed
    call_arg->resp_vaddr = 0;
    call_arg->resp_size = 0;
    goto restore_return_val;
  }
  pma = vma->pma;
  delete_vma(&(enclave->mmap_vma), vma);
  delete_pma(&(enclave->pma_list), pma);
  unmap((uintptr_t*)(enclave->root_page_table), vma->va_start, vma->va_end - vma->va_start);
  vma->vm_next = NULL;
  pma->pm_next = NULL;
  if(caller_enclave->mmap_vma)
    vma->va_end = caller_enclave->mmap_vma->va_start;
  else
    vma->va_end = ENCLAVE_DEFAULT_MMAP_BASE;
  vma->va_start = vma->va_end - (pma->size - RISCV_PGSIZE);
  vma->vm_next = caller_enclave->mmap_vma;
  caller_enclave->mmap_vma = vma;
  insert_pma(&(caller_enclave->pma_list), pma);
  mmap((uintptr_t*)(caller_enclave->root_page_table), &(caller_enclave->free_pages), vma->va_start, pma->paddr + RISCV_PGSIZE, pma->size - RISCV_PGSIZE);
  call_arg->resp_vaddr = vma->va_start;
  call_arg->resp_size = ret_arg.resp_size;

  //pass return value of server
restore_return_val:
  call_arg->resp_val = ret_arg.resp_val;
  enclave->state = RUNNABLE;
  caller_enclave->state = RUNNING;
  ret = 0;
out:
  release_enclave_metadata_lock();
  return ret;
}

/**************************************************************/
/*                   called when irq                          */
/**************************************************************/
/**
 * \brief Handle the time interrupt for enclave.
 * 
 * \param regs The enclave register context.
 * \param mcause CSR register of mcause.
 * \param mepc CSR register of the mepc.
 */
uintptr_t do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc)
{
  uintptr_t retval = 0;
  unsigned int eid = get_curr_enclave_id();
  struct enclave_t *enclave = NULL;

  acquire_enclave_metadata_lock();

  // Enclave need to be destroyed or stopped, ignore this time irq
  if (NEED_DESTORY_ENCLAVE[csr_read(CSR_MHARTID)] == 1 || NEED_STOP_ENCLAVE[csr_read(CSR_MHARTID)] == 1)
  {
    release_enclave_metadata_lock();
    return retval;
  }

  enclave = __get_enclave(eid);
  if(!enclave || enclave->state != RUNNING)
  {
    sbi_bug("M mode: do_timer_irq: something is wrong with enclave%d, state: %d\n", eid, enclave->state);
    retval = -1UL;
    goto timer_irq_out;
  }
   swap_from_enclave_to_host(regs, enclave);
   enclave->state = RUNNABLE;

timer_irq_out:
  release_enclave_metadata_lock();

  csr_read_clear(CSR_MIE, MIP_MTIP);
  csr_read_set(CSR_MIP, MIP_STIP);
  regs[10] = ENCLAVE_TIMER_IRQ;
  retval = ENCLAVE_TIMER_IRQ;
  return retval;
}

/**
 * \brief (remove) Handle the yield() in enclave during the runtime.
 * 
 * \param regs The enclave register context.
 * \param mcause CSR register of mcause.
 * \param mepc CSR register of the mepc.
 */
uintptr_t do_yield(uintptr_t *regs)
{
  uintptr_t retval = 0;
  unsigned int eid = get_curr_enclave_id();
  struct enclave_t *enclave = NULL;

  acquire_enclave_metadata_lock();

  enclave = __get_enclave(eid);
  if(!enclave || enclave->state != RUNNING)
  {
    sbi_bug("M mode: do_yield: something is wrong with enclave%d\n", eid);
    retval = -1UL;
    goto timer_irq_out;
  }

  swap_from_enclave_to_host(regs, enclave);
  enclave->state = RUNNABLE;

timer_irq_out:
  release_enclave_metadata_lock();
  retval = ENCLAVE_YIELD;
  return retval;
}

/**
 * \brief IPI notifaction to destroy enclave, check whether the target enclave is running.
 * 
 * \param regs The enclave register context.
 * \param host_ptbr host ptbr register.
 * \param eid The enclave id.
 */
uintptr_t ipi_destroy_enclave(uintptr_t *regs, uintptr_t host_ptbr, int eid)
{
  uintptr_t ret = 0;
  struct enclave_t* enclave = NULL;
  struct pm_area_struct* pma = NULL;
  int need_free_enclave_memory = 0;

  // TODO acquire the enclave metadata lock
  acquire_enclave_metadata_lock();

  enclave = __get_enclave(eid);

  unsigned long mm_arg_paddr[RELAY_PAGE_NUM];
  unsigned long mm_arg_size[RELAY_PAGE_NUM];
  for(int kk = 0; kk < RELAY_PAGE_NUM; kk++)
  {
    mm_arg_paddr[kk] = enclave->mm_arg_paddr[kk];
    mm_arg_size[kk] = enclave->mm_arg_size[kk];
  }

  //enclave may have exited or even assigned to other host
  //after ipi sender release the enclave_metadata_lock
  if(!enclave || enclave->state < FRESH)
  {
    ret = -1;
    sbi_bug("M mode: ipi_destroy_enclave: enclave is not existed or is illegal to destroy!\n");
    goto ipi_destroy_enclave_out;
  }

  //this situation should never happen
  if(check_in_enclave_world() < 0 || enclave->state != RUNNING || cpus[csr_read(CSR_MHARTID)].eid != eid || (enclave->host_ptbr != host_ptbr))
  {
    sbi_bug("[ERROR] M mode: ipi_destroy_enclave: this situation should never happen!\n");
    ret = -1;
    goto ipi_destroy_enclave_out;
  }

  swap_from_enclave_to_host(regs, enclave);
  //regs[10] = ENCLAVE_DESTROYED;
  regs[10] = 0;
  
  pma = enclave->pma_list;
  need_free_enclave_memory = 1;
  __free_enclave(eid);
  NEED_DESTORY_ENCLAVE[csr_read(CSR_MHARTID)] =0;

ipi_destroy_enclave_out:
  release_enclave_metadata_lock();

  if(need_free_enclave_memory)
  {
    free_enclave_memory(pma);
    free_all_relay_page(mm_arg_paddr, mm_arg_size);
  }
  regs[10] = 0;
	regs[11] = 0;
  return ret;
}

/**
 * \brief IPI notifaction to stop enclave, check wether the target enclave is running.
 * 
 * \param regs The enclave register context.
 * \param host_ptbr host ptbr register.
 * \param eid The enclave id.
 */
uintptr_t ipi_stop_enclave(uintptr_t *regs, uintptr_t host_ptbr, int eid)
{
  uintptr_t ret = 0;
  struct enclave_t* enclave = NULL;

  acquire_enclave_metadata_lock();
  
  enclave = __get_enclave(eid);
  //enclave may have exited or even assigned to other host
  //after ipi sender release the enclave_metadata_lock
  if(!enclave || enclave->state <= FRESH || enclave->state == OCALLING)
  {
    sbi_bug("M mode: ipi_stop_enclave: enclave is not existed or is illegal to stop!\n");
    ret = -1UL;
    goto ipi_stop_enclave_out;
  }

  //this situation should never happen
  if(check_in_enclave_world() < 0 || enclave->host_ptbr != host_ptbr || enclave->state != RUNNING ||  cpus[csr_read(CSR_MHARTID)].eid != eid)
  {
    sbi_bug("M mode: ipi_stop_enclave: this situation should never happen!\n");
    ret = -1;
    goto ipi_stop_enclave_out;
  }

  swap_from_enclave_to_host(regs, enclave);
  regs[10] = ENCLAVE_TIMER_IRQ;
  ret = ENCLAVE_TIMER_IRQ;
  
  enclave->state = STOPPED;
  NEED_STOP_ENCLAVE[csr_read(CSR_MHARTID)] = 0;
ipi_stop_enclave_out:
  release_enclave_metadata_lock();
  return ret;
}


/**
 * \brief Enclave call read() in the runtime, ocall to the host to handle.
 * 
 * \param regs The enclave register context.
 */
uintptr_t enclave_read_sec(uintptr_t *regs, uintptr_t sec){
  uintptr_t ret = 0;
  int eid = get_curr_enclave_id();
  struct enclave_t *enclave = NULL;
  if(check_in_enclave_world() < 0){
    return -1;
  }
  acquire_enclave_metadata_lock();
  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave) != 0 || enclave->state != RUNNING){
    ret = -1;
    goto out;
  }
  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_READ_SECT);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, sec);
  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;

out:
  release_enclave_metadata_lock();
  return ret;

}

/**
 * \brief Enclave call write() in the runtime, ocall to the host to handle.
 * 
 * \param regs The enclave register context.
 */
uintptr_t enclave_write_sec(uintptr_t *regs, uintptr_t sec){
  uintptr_t ret = 0;
  int eid = get_curr_enclave_id();
  struct enclave_t *enclave = NULL;
  if(check_in_enclave_world() < 0){
    return -1;
  }
  acquire_enclave_metadata_lock();
  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave) != 0|| enclave->state != RUNNING){
    ret = -1;
    goto out;
  }
  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_WRITE_SECT);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0,sec);
  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;

out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief Enclave return the relay page to host, unmap these pages and back to the host.
 * 
 * \param regs The enclave register context.
 */
uintptr_t enclave_return_relay_page(uintptr_t *regs)
{
  uintptr_t ret = 0;
  int eid = get_curr_enclave_id();
  struct enclave_t *enclave = NULL;
  if(check_in_enclave_world() < 0){
    return -1;
  }
  acquire_enclave_metadata_lock();
  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave) != 0|| enclave->state != RUNNING){
    ret = -1;
    sbi_bug("M mode: enclave_return_relay_page: check enclave is failed\n");
    goto out;
  }

  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_RETURN_RELAY_PAGE);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0,enclave->mm_arg_paddr[0]);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg1,enclave->mm_arg_size[0]);
  //remap the relay page for host
  for(int kk = 0; kk < RELAY_PAGE_NUM; kk++)
  {
    if (enclave->mm_arg_paddr[kk])
    {
      __free_secure_memory(enclave->mm_arg_paddr[kk], enclave->mm_arg_size[kk]);
      __free_relay_page_entry(enclave->mm_arg_paddr[kk], enclave->mm_arg_size[kk]);
      unmap((uintptr_t*)(enclave->root_page_table), ENCLAVE_DEFAULT_MM_ARG_BASE, enclave->mm_arg_size[kk]);
    }
  }
  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;

out:
  release_enclave_metadata_lock();
  // sbi_printf("out of enclave_return_relay_page now\n");
  return ret;
}

/**
 * \brief Generate a random value for enclave.
 * 
 * \param regs The enclave register context
 * \param random_buff Receiving buff for the random value
 * \param size The size of random value 
 */
uintptr_t enclave_getrandom(uintptr_t *regs, uintptr_t random_buff, uintptr_t size)
{
  uintptr_t ret = 0;
  int eid = get_curr_enclave_id();
  struct enclave_t *enclave = NULL;
  uintptr_t * p_random_buff = 0;

  if(check_in_enclave_world() < 0){
    return -1;
  }

  acquire_enclave_metadata_lock();
  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave) != 0|| enclave->state != RUNNING){
    ret = -1;
    sbi_debug("[ERROR] M mode: enclave_getrandom: check enclave is failed\r\n");
    goto out;
  }

  p_random_buff = va_to_pa((uintptr_t*)(enclave->root_page_table), (void*)random_buff);
  ret = platform_getrand((char *) p_random_buff, size);

out:
  release_enclave_metadata_lock();
  return ret;
}


/**
 * todo: add PE ocalls.
 * by Anonymous Author @ May 8, 2023.
*/

/**
 * \brief This transitional function transfer PE's create_enclave Ocall to host.
 * 
 * \param regs The PE context
 * \param enclave_create_args The enclave create arguments (VA)
 */
uintptr_t privil_create_enclave(uintptr_t* regs, uintptr_t enclave_create_args)
{
  /* sanity check: caller should be an active PE */
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL; // current running enclave, should be PE.
  int eid = 0; 
  unsigned remain_page_size;
  unsigned param_size = sizeof(ocall_create_param_t);
  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: privil_create_enclave: CPU is not in the enclave mode\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();
  
  /* slab-level eid */
  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if( !enclave || 
      check_enclave_authentication(enclave)!=0 || 
      enclave->state != RUNNING || 
      enclave->type != PRIVIL_ENCLAVE)
  {
    // early reject.
    ret = -1UL;
    sbi_bug("M mode: privil_create_enclave: enclave%d can not be accessed!\n", eid);
    goto out;
  }
  
  void *create_args = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)enclave_create_args);
  if (!create_args) 
  {
    ret = -1UL;
    sbi_bug("M mode: privil_create_enclave: enclave_create_args pointer is not valid\n");
    goto out;
  }
  /* pass the slab eid */
  ((ocall_create_param_t *)create_args)->eid = eid;

  /* Avoid same-VA-page but diff-PA-page situation. */
  remain_page_size = PAGE_SIZE - (enclave_create_args & (PAGE_SIZE-1));
  if (param_size > remain_page_size) 
  {
    copy_to_host((void*)(enclave->kbuffer), create_args, remain_page_size);
    copy_to_host((void*)(enclave->kbuffer+remain_page_size), 
                 va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(enclave_create_args+remain_page_size)),
                 param_size - remain_page_size);
  } 
  else 
  {
    copy_to_host((void*)(enclave->kbuffer), create_args, param_size);
  }

  uintptr_t state_va = ((ocall_create_param_t *)create_args)->migrate_arg;
  if (state_va)
  {
    void *state_pa = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)state_va);
    void *state_buf = (void *)(enclave->kbuffer + sizeof(ocall_create_param_t));

    param_size = sizeof(snapshot_state_t);
    remain_page_size = PAGE_SIZE - (state_va & (PAGE_SIZE-1));
    if (param_size > remain_page_size)
    {
      copy_to_host(state_buf, state_pa, remain_page_size);
      copy_to_host((void *)(state_buf + remain_page_size),
                    va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(state_va+remain_page_size)),
                    param_size - remain_page_size);
    }
    else 
    {
      copy_to_host(state_buf, state_pa, param_size);
    }

  }


  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_CREATE_ENCLAVE);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, enclave->kbuffer);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, (uintptr_t)enclave_create_args);

  
  /* return to host with Ocall identity */
  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;
out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief This transitional function is used to attest the NE.
 * 
 * \param regs The PE context
 * \param enclave_attest_args attest param (VA)
 * \param tgt_eid The target enclave id. (idr)
 * \param report_ptr The enclave measurement report pointer from PE. (VA)
 * \param nonce The attestation nonce.
 */
uintptr_t privil_attest_enclave(uintptr_t* regs, uintptr_t enclave_attest_args)
{
  /* sanity check: caller should be an active PE */
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL; // current running enclave, should be PE.
  int eid = 0; 
  unsigned remain_page_size;
  // unsigned param_size = sizeof(enclave_create_param_t) + ELF_FILE_LEN;
  unsigned param_size = sizeof(ocall_attest_param_t);
  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: privil_attest_enclave: CPU is not in the enclave mode\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();
  /* slab-level eid */
  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if( !enclave || 
      check_enclave_authentication(enclave)!=0 || 
      enclave->state != RUNNING || 
      enclave->type != PRIVIL_ENCLAVE)
  {
    // early reject.
    ret = -1UL;
    sbi_bug("M mode: privil_attest_enclave: enclave%d can not be accessed!\n", eid);
    goto out;
  }

  void *attest_args = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)enclave_attest_args);
  if (!attest_args) 
  {
    ret = -1UL;
    sbi_bug("M mode: privil_attest_enclave: enclave_attest_args pointer is not valid\n");
    goto out;
  }
  ((ocall_attest_param_t *)attest_args)->current_eid = get_curr_enclave_id();

  /* Avoid same-VA-page but diff-PA-page situation. */
  remain_page_size = PAGE_SIZE - (enclave_attest_args & (PAGE_SIZE-1));
  if (param_size > remain_page_size) 
  {
    copy_to_host((void*)(enclave->kbuffer), attest_args, remain_page_size);
    copy_to_host((void*)(enclave->kbuffer+remain_page_size), 
                 va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(enclave_attest_args+remain_page_size)),
                 param_size - remain_page_size);
  } 
  else 
  {
    copy_to_host((void*)(enclave->kbuffer), attest_args, param_size);
  }

  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_ATTEST_ENCLAVE);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, enclave->kbuffer);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, (uintptr_t)enclave_attest_args);

  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;

out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief This transitional function is used to enter the NE.
 * 
 * \param regs The regs context
 * \param enclave_run_args The run parameter (VA)
 */
uintptr_t privil_run_enclave(uintptr_t* regs, uintptr_t enclave_run_args)
{
  /* sanity check: caller should be an active PE */
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL; // current running enclave, should be PE.
  int eid = 0; 
  unsigned remain_page_size;
  unsigned param_size = sizeof(ocall_run_param_t);

  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: privil_run_enclave: CPU is not in the enclave mode\n");
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  /* slab-level eid */
  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if( !enclave || 
      check_enclave_authentication(enclave)!=0 || 
      enclave->state != RUNNING || 
      enclave->type != PRIVIL_ENCLAVE)
  {
    // early reject.
    ret = -1UL;
    sbi_bug("M mode: privil_run_enclave: enclave%d can not be accessed!\n", eid);
    goto out;
  }

  void *run_args = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)enclave_run_args);
  if (!run_args)
  {
    ret = -1UL;
    sbi_bug("M mode: privil_run_enclave: enclave_run_args pointer is not valid\n");
    goto out;
  }
  /* pass the slab eid? */

  /* Avoid same-VA-page but diff-PA-page situation. */
  remain_page_size = PAGE_SIZE - (enclave_run_args & (PAGE_SIZE-1));
  if (param_size > remain_page_size) 
  {
    copy_to_host((void*)(enclave->kbuffer), run_args, remain_page_size);
    copy_to_host((void*)(enclave->kbuffer+remain_page_size), 
                 va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(enclave_run_args+remain_page_size)),
                 param_size - remain_page_size);
  } 
  else 
  {
    copy_to_host((void*)(enclave->kbuffer), run_args, param_size);
  }
  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_RUN_ENCLAVE);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, enclave->kbuffer);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, (uintptr_t)enclave_run_args);

  /* freeze PE, stay OCALLing */
  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;
out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief This transitional function is used to stop the NE.
 * 
 * \param regs The regs context
 * \param eid   The enclave id
 */
uintptr_t privil_stop_enclave(uintptr_t* regs, uintptr_t eid) 
{
  // uintptr_t cur_eid;
  uintptr_t ret = 0;
  // uintptr_t dest_hart = 0;
//   struct enclave_t *cur_enclave = NULL;
//   struct enclave_t *tgt_enclave = NULL;
//   if(check_in_enclave_world() < 0)
//   {
//     sbi_bug("M mode: privil_stop_enclave: should not be called by host itself\n");
//     return -1UL;
//   }
//   acquire_enclave_metadata_lock();
//   cur_eid = get_curr_enclave_id();
//   cur_enclave = __get_enclave(cur_eid);
//   tgt_enclave = __get_enclave(eid);

//   if(!tgt_enclave || 
//       tgt_enclave->state <= FRESH || tgt_enclave->state == ATTESTING || tgt_enclave->state == OCALLING || 
//       tgt_enclave->host_ptbr != csr_read(CSR_SATP) || 
//       tgt_enclave->type == SERVER_ENCLAVE || 
//       cur_enclave->type != PRIVIL_ENCLAVE || 
//       tgt_enclave->parent_eid != cur_eid)
//   {
//     sbi_bug("M mode: privil_stop_enclave: enclave%d can not be accessed!\n", eid);
//     ret = -1UL;
//     goto stop_enclave_out;
//   }

//   // temporarily...
//   if(tgt_enclave->state != RUNNING)
//   {
//     tgt_enclave->state = STOPPED;
//     release_enclave_metadata_lock();
//   }
//   else
//   {
//     //cpus' state will be protected by enclave_metadata_lock
//     for(int i = 0; i < MAX_HARTS; ++i)
//     {
//       if(cpus[i].in_enclave && cpus[i].eid == eid)
//         dest_hart = i;
//     }
//     if (dest_hart == csr_read(CSR_MHARTID))
//     {
//       NEED_STOP_ENCLAVE[dest_hart] = 1;
//       release_enclave_metadata_lock();
//       ipi_stop_enclave(regs, csr_read(CSR_SATP), eid);
//     }
//     else
//     {
//       NEED_STOP_ENCLAVE[dest_hart] = 1;
//       release_enclave_metadata_lock();
//       set_ipi_stop_enclave_and_sync(dest_hart, csr_read(CSR_SATP), eid);
//     }
//   }

// stop_enclave_out:
  return ret;

  /* use ipi to stop enclave in other harts, kind of complicated. */
}

/**
 * \brief This transitional function is used to resume the NE.
 * 
 * \param regs The regs context
 * \param enclave_resume_args   The resume parameter (VA)
 */
uintptr_t privil_resume_enclave(uintptr_t* regs, uintptr_t enclave_resume_args)
{
  /* sanity check: caller should be an active PE */
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL; // current running enclave, should be PE.
  int eid = 0; 
  unsigned remain_page_size;
  unsigned param_size = sizeof(ocall_run_param_t);

  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: privil_resume_enclave: CPU is not in the enclave mode\n");
    return -1UL;
  }
  acquire_enclave_metadata_lock();

  /* slab-level eid */
  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if( !enclave || 
      check_enclave_authentication(enclave)!=0 || 
      enclave->state != RUNNING || 
      enclave->type != PRIVIL_ENCLAVE)
  {
    // early reject.
    ret = -1UL;
    sbi_bug("M mode: privil_resume_enclave: enclave%d can not be accessed!\n", eid);
    goto out;
  }

  void *resume_args = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)enclave_resume_args);
  if (!resume_args)
  {
    ret = -1UL;
    sbi_bug("M mode: privil_resume_enclave: enclave_resume_args pointer is not valid\n");
    goto out;
  }

  /* Avoid same-VA-page but diff-PA-page situation. */
  remain_page_size = PAGE_SIZE - (enclave_resume_args & (PAGE_SIZE-1));
  if (param_size > remain_page_size) 
  {
    copy_to_host((void*)(enclave->kbuffer), resume_args, remain_page_size);
    copy_to_host((void*)(enclave->kbuffer+remain_page_size), 
                 va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(enclave_resume_args+remain_page_size)),
                 param_size - remain_page_size);
  } 
  else 
  {
    copy_to_host((void*)(enclave->kbuffer), resume_args, param_size);
  }
  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_RESUME_ENCLAVE);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, enclave->kbuffer);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, (uintptr_t)enclave_resume_args);

  /* freeze PE, stay OCALLing */
  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;
out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief This transitional function is used to destroy the NE.
 * 
 * \param regs The host register context.
 * \param tgt_eid Destroyed enclave id. (idr-allocated)
 * \param op The additional destroy operation
 */
uintptr_t privil_destroy_enclave(uintptr_t* regs, uintptr_t enclave_destroy_args)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL; // current running enclave, should be PE.
  int cur_eid = 0; 
  unsigned remain_page_size;
  unsigned param_size = sizeof(ocall_destroy_param_t);

  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: privil_destroy_enclave: CPU is not in the enclave mode\n");
    return -1UL;
  }
  acquire_enclave_metadata_lock();
  cur_eid = get_curr_enclave_id();
  enclave = __get_enclave(cur_eid);
  if( !enclave || 
      check_enclave_authentication(enclave)!=0 || 
      enclave->state != RUNNING || 
      enclave->type != PRIVIL_ENCLAVE)
  {
    // early reject.
    ret = -1UL;
    sbi_bug("M mode: privil_resume_enclave: enclave can not be accessed!\n");
    goto out;
  }

  void *destroy_args = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)enclave_destroy_args);
  if (!destroy_args)
  {
    ret = -1UL;
    sbi_bug("M mode: privil_destroy_enclave: enclave_destroy_args pointer is not valid\n");
    goto out;
  }
  remain_page_size = PAGE_SIZE - (enclave_destroy_args & (PAGE_SIZE-1));
  if (param_size > remain_page_size)
  {
    copy_to_host((void *)(enclave->kbuffer), destroy_args, remain_page_size);
    copy_to_host((void *)(enclave->kbuffer+remain_page_size),
                  va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(enclave_destroy_args+remain_page_size)), 
                  param_size - remain_page_size);
  }
  else 
  {
    copy_to_host((void *)(enclave->kbuffer), destroy_args, param_size);
  }
  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_DESTROY_ENCLAVE);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, enclave->kbuffer);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, (uintptr_t)enclave_destroy_args);

  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;
out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief This transitional function is used to inspect the NE.
 * 
 * \param regs The host register context.
 * \param enclave_inspect_args   The inspect parameter (VA)
*/
uintptr_t privil_inspect_enclave(uintptr_t* regs, uintptr_t enclave_inspect_args)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL; // current running enclave, should be PE.
  int eid = 0; 
  unsigned remain_page_size;
  unsigned param_size = sizeof(ocall_inspect_param_t);

  if(check_in_enclave_world() < 0)
  {
    sbi_bug("M mode: privil_inspect_enclave: CPU is not in the enclave mode\n");
    return -1UL;
  }
  acquire_enclave_metadata_lock();

  /* slab-level eid */
  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if( !enclave || 
      check_enclave_authentication(enclave)!=0 || 
      enclave->state != RUNNING || 
      enclave->type != PRIVIL_ENCLAVE)
  {
    // early reject.
    ret = -1UL;
    sbi_bug("M mode: privil_inspect_enclave: enclave%d can not be accessed!\n", eid);
    goto out;
  }
  void *inspect_args = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)enclave_inspect_args);
  if (!inspect_args)
  {
    ret = -1UL;
    sbi_bug("M mode: privil_inspect_enclave: enclave_inspect_args pointer is not valid\n");
    goto out;
  }

  /* Avoid same-VA-page but diff-PA-page situation. */
  remain_page_size = PAGE_SIZE - (enclave_inspect_args & (PAGE_SIZE-1));
  if (param_size > remain_page_size) 
  {
    copy_to_host((void*)(enclave->kbuffer), inspect_args, remain_page_size);
    copy_to_host((void*)(enclave->kbuffer+remain_page_size), 
                 va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)(enclave_inspect_args+remain_page_size)),
                 param_size - remain_page_size);
  } 
  else 
  {
    copy_to_host((void*)(enclave->kbuffer), inspect_args, param_size);
  }
  copy_dword_to_host((uintptr_t*)enclave->ocall_func_id, OCALL_INSPECT_ENCLAVE);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, enclave->kbuffer);
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, (uintptr_t)enclave_inspect_args);

  swap_from_enclave_to_host(regs, enclave);
  enclave->state = OCALLING;
  ret = ENCLAVE_OCALL;
out:
  release_enclave_metadata_lock();
  return ret;
}

/**
 * \brief This transitional function is used to pause the NE itself and return to PE.
 * 
 * \param regs The host register context.
 * \param enclave_pause_args   The pause parameter (VA)
 * 
 * \details This primitive should only be called by NE that governed by PE for now.
 * It's also explainable for pausing other legacy enclave designs, but we leave it as our future work.
 * by Anonymous Author @ May 17, 2023.
*/
uintptr_t privil_pause_enclave(uintptr_t* regs, uintptr_t enclave_pause_args)
{
  struct enclave_t *enclave = NULL;
  int eid = 0;
  uintptr_t ret = 0;
  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = __get_enclave(eid);
  if(!enclave || check_enclave_authentication(enclave) != 0 || enclave->type != NORMAL_ENCLAVE)
  {
    sbi_bug("M mode: privil_pause_enclave: enclave%d can not be accessed!\n", eid);
    ret = -1UL;
    goto pause_enclave_out;
  }
  /** 
   * Copy to ocall_func_id is useless now, since we don't enter penglai_enclave_ocall.
   * Instead, we jump back to PE's handle_ocall_run_enclave.
  */
  void *pause_args = va_to_pa((uintptr_t *)(enclave->root_page_table), (void *)enclave_pause_args);
  if (!pause_args)
  {
    ret = -1UL;
    sbi_bug("M mode: privil_pause_enclave: enclave_pause_args pointer is not valid\n");
    goto pause_enclave_out;
  }
  ocall_request_t *ocall_request = (ocall_request_t *)pause_args;
  copy_dword_to_host((uintptr_t*)enclave->ocall_arg0, ocall_request->request);
  copy_dword_to_host((uintptr_t*)enclave->retval, (uintptr_t)enclave_pause_args);

  swap_from_enclave_to_host(regs, enclave);
  // enclave->state = OCALLING;
  enclave->state = STOPPED;
  /* We mark return value as REQUEST to distinguish it from normal OCALL. */
  ret = ENCLAVE_NE_REQUEST;
pause_enclave_out:
  release_enclave_metadata_lock();
  return ret;  
}