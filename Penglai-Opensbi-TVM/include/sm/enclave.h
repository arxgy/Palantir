#ifndef _ENCLAVE_H
#define _ENCLAVE_H

#include "sbi/riscv_encoding.h"
#include "sm/enclave_args.h"
#include "sbi/riscv_atomic.h" 
#include "sbi/riscv_locks.h"
#include "sbi/sbi_string.h"
#include "sbi/riscv_asm.h"
#include "sbi/sbi_types.h"
#include "sm/thread.h"
#include "sm/vm.h"



#define ENCLAVES_PER_METADATA_REGION 100
#define ENCLAVE_METADATA_REGION_SIZE ((sizeof(struct enclave_t)) * ENCLAVES_PER_METADATA_REGION)
#define SHADOW_ENCLAVE_METADATA_REGION_SIZE ((sizeof(struct shadow_enclave_t)) * ENCLAVES_PER_METADATA_REGION)
#define RELAY_PAGE_NUM 10
#define MAX_HARTS 8
#define ENCLAVE_MODE 1
#define NORMAL_MODE 0

//FIXME: need to determine the suitable threshold depending on the performance.
#define ENCLAVE_SELF_HASH_THRESHOLD  (RISCV_PGSIZE)

//FIXME: entry point of self hash code, may need to change for some unknown reasons.
#define ENCLAVE_SELF_HASH_ENTRY  (0x8000)

#define SET_ENCLAVE_METADATA(point, enclave, create_args, struct_type, base) do { \
  enclave->entry_point = point; \
  enclave->ocall_func_id = ((struct_type)create_args)->ecall_arg0; \
  enclave->ocall_arg0 = ((struct_type)create_args)->ecall_arg1; \
  enclave->ocall_arg1 = ((struct_type)create_args)->ecall_arg2; \
  enclave->ocall_syscall_num = ((struct_type)create_args)->ecall_arg3; \
  enclave->retval = ((struct_type)create_args)->retval; \
  enclave->kbuffer = ((struct_type)create_args)->kbuffer; \
  enclave->kbuffer_size = ((struct_type)create_args)->kbuffer_size; \
  enclave->shm_paddr = ((struct_type)create_args)->shm_paddr; \
  enclave->shm_size = ((struct_type)create_args)->shm_size; \
  enclave->host_ptbr = csr_read(CSR_SATP); \
  enclave->root_page_table = ((struct_type)create_args)->base + RISCV_PGSIZE; \
  enclave->thread_context.encl_ptbr = ((((struct_type)create_args)->base+RISCV_PGSIZE) >> RISCV_PGSHIFT) | SATP_MODE_CHOICE; \
  enclave->type = NORMAL_ENCLAVE; \
  enclave->state = FRESH; \
  enclave->caller_eid = -1; \
  enclave->top_caller_eid = -1; \
  enclave->cur_callee_eid = -1; \
  enclave->ocalling_shm_key = 0; \
  sbi_memcpy(enclave->enclave_name, ((struct_type)create_args)->name, NAME_LEN); \
} while(0)

struct link_mem_t
{
  unsigned long mem_size;
  unsigned long slab_size;
  unsigned long slab_num;
  char* addr;
  struct link_mem_t* next_link_mem;    
};


enum key_type_t {
    ENCLAVE_KEY = 0,
    STORAGE_KEY,
    ATTEST_KEY
};

typedef enum 
{
  DESTROYED = -1,
  INVALID = 0,
  FRESH = 1,
  RUNNABLE,
  RUNNING,
  STOPPED, 
  ATTESTING,
  OCALLING
} enclave_state_t;

struct vm_area_struct
{
  unsigned long va_start;
  unsigned long va_end;

  struct vm_area_struct *vm_next;
  struct pm_area_struct *pma;
};

struct pm_area_struct
{
  unsigned long paddr;
  unsigned long size;
  unsigned long free_mem;

  struct pm_area_struct *pm_next;
};

struct page_t
{
  uintptr_t paddr;
  struct page_t *next;
};

struct enclave_t
{
  unsigned int eid;
  enclave_type_t type;
  enclave_state_t state;

  //vm_area_struct lists
  struct vm_area_struct* text_vma;
  struct vm_area_struct* stack_vma;
  uintptr_t _stack_top; //lowest address of stack area
  struct vm_area_struct* heap_vma;
  uintptr_t _heap_top;  //highest address of heap area
  struct vm_area_struct* mmap_vma;
  struct vm_area_struct* sec_shm_vma;

  //pm_area_struct list
  struct pm_area_struct* pma_list;
  struct page_t* free_pages;
  uintptr_t free_pages_num;

  //root page table of enclave
  unsigned long root_page_table;

  //root page table register for host
  unsigned long host_ptbr;

  //entry point of enclave
  unsigned long entry_point;

  //shared mem with kernel
  unsigned long kbuffer;//paddr
  unsigned long kbuffer_size;

  //shared mem with host
  unsigned long shm_paddr;
  unsigned long shm_size;

  // host memory arg
  unsigned long mm_arg_paddr[RELAY_PAGE_NUM];
  unsigned long mm_arg_size[RELAY_PAGE_NUM];

  unsigned long* ocall_func_id;
  unsigned long* ocall_arg0;
  unsigned long* ocall_arg1;
  unsigned long* ocall_syscall_num;
  unsigned long* retval;
  unsigned long ocalling_shm_key;
  unsigned long checkpoint_num;
  unsigned long relay_page_offset;
  // enclave thread context
  // TODO: support multiple threads
  struct thread_state_t thread_context;
  unsigned int top_caller_eid;
  unsigned int caller_eid;
  unsigned int cur_callee_eid;
  unsigned char hash[HASH_SIZE];
  char enclave_name[NAME_LEN];
};

struct shadow_enclave_t
{
  unsigned int eid;

  enclave_state_t state;
  unsigned long paddr;
  unsigned long size;

  //root page table of enclave
  unsigned long root_page_table;

  //root page table register for host
  unsigned long host_ptbr;

  //entry point of enclave
  unsigned long entry_point;
  struct thread_state_t thread_context;
  unsigned char hash[HASH_SIZE];
};

/**
 * cpu state
 */
struct cpu_state_t
{
  int in_enclave; // whether current hart is in enclave-mode
  int eid; // the eid of current enclave if the hart in enclave-mode
};

void acquire_enclave_metadata_lock();
void release_enclave_metadata_lock();

int cpu_in_enclave(int i);
int cpu_eid(int i);
int check_in_enclave_world();
int get_curr_enclave_id();
struct enclave_t* __get_enclave(int eid);
struct enclave_t* __get_real_enclave(int eid);

uintptr_t copy_from_host(void* dest, void* src, size_t size);
uintptr_t copy_to_host(void* dest, void* src, size_t size);
int copy_word_to_host(unsigned int* ptr, uintptr_t value);
int copy_dword_to_host(uintptr_t* ptr, uintptr_t value);

struct link_mem_t* init_mem_link(unsigned long mem_size, unsigned long slab_size);
struct link_mem_t* add_link_mem(struct link_mem_t** tail);

struct enclave_t* __alloc_enclave();
int __free_enclave(int eid);
void free_enclave_memory(struct pm_area_struct *pma);

// Called by host
// Enclave-related operations
uintptr_t create_enclave(enclave_create_param_t create_args);
uintptr_t attest_enclave(uintptr_t eid, uintptr_t report, uintptr_t nonce);
uintptr_t run_enclave(uintptr_t* regs, unsigned int eid, enclave_run_param_t enclave_run_param);
uintptr_t stop_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t wake_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t destroy_enclave(uintptr_t* regs, unsigned int eid);

// Shadow encalve related operations
uintptr_t create_shadow_enclave(enclave_create_param_t create_args);
uintptr_t attest_shadow_enclave(uintptr_t eid, uintptr_t report, uintptr_t nonce);
uintptr_t destroy_shadow_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t run_shadow_enclave(uintptr_t* regs, unsigned int eid, shadow_enclave_run_param_t enclave_run_param);

// Resume enclave
uintptr_t resume_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t resume_from_ocall(uintptr_t* regs, unsigned int eid);


struct call_enclave_arg_t
{
  uintptr_t req_arg;
  uintptr_t resp_val;
  uintptr_t req_vaddr;
  uintptr_t req_size;
  uintptr_t resp_vaddr;
  uintptr_t resp_size;
};

// Called by enclave
uintptr_t call_enclave(uintptr_t *regs, unsigned int enclave_id, uintptr_t arg);
uintptr_t enclave_return(uintptr_t *regs, uintptr_t arg);
uintptr_t asyn_enclave_call(uintptr_t *regs, uintptr_t enclave_name, uintptr_t arg);
uintptr_t split_mem_region(uintptr_t *regs, uintptr_t mem_addr, uintptr_t mem_size, uintptr_t split_addr);
uintptr_t exit_enclave(uintptr_t* regs, unsigned long retval);
uintptr_t get_enclave_attest_report(uintptr_t *report, uintptr_t nonce);
uintptr_t derive_key(uintptr_t key_type, uintptr_t *key, uintptr_t key_size);
// Ocall operations
uintptr_t enclave_mmap(uintptr_t* regs, uintptr_t vaddr, uintptr_t size);
uintptr_t enclave_unmap(uintptr_t* regs, uintptr_t vaddr, uintptr_t size);
uintptr_t enclave_sys_write(uintptr_t *regs);
uintptr_t enclave_sbrk(uintptr_t* regs, intptr_t size);
uintptr_t enclave_read_sec(uintptr_t *regs, uintptr_t sec);
uintptr_t enclave_write_sec(uintptr_t *regs, uintptr_t sec);
uintptr_t enclave_return_relay_page(uintptr_t *regs);
uintptr_t enclave_getrandom(uintptr_t *regs, uintptr_t random_buff, uintptr_t size);
uintptr_t do_yield(uintptr_t* regs);
//TODO: flags in enclave shared memory not being used now.
uintptr_t enclave_shmget(uintptr_t* regs, uintptr_t key, uintptr_t size, uintptr_t flags);
uintptr_t shmget_after_resume(struct enclave_t *enclave, uintptr_t paddr, uintptr_t size);
uintptr_t shmextend_after_resume(struct enclave_t *enclave, uintptr_t status);
uintptr_t sm_shm_attatch(uintptr_t* regs, uintptr_t key);
uintptr_t enclave_shmdetach(uintptr_t* regs, uintptr_t key);
uintptr_t enclave_shmdestroy(uintptr_t* regs, uintptr_t key);
uintptr_t sm_shm_stat(uintptr_t* regs, uintptr_t key, uintptr_t shm_desp_user);

// IPI
uintptr_t ipi_stop_enclave(uintptr_t *regs, uintptr_t host_ptbr, int eid);
uintptr_t ipi_destroy_enclave(uintptr_t *regs, uintptr_t host_ptbr, int eid);

// Timer IRQ
uintptr_t do_timer_irq(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc);

// Relay page
struct relay_page_entry_t* __get_relay_page_by_name(char* enclave_name, int *slab_index, int *link_mem_index);
int __free_relay_page_entry(unsigned long relay_page_addr, unsigned long relay_page_size);
struct relay_page_entry_t* __alloc_relay_page_entry(char *enclave_name, unsigned long relay_page_addr, unsigned long relay_page_size);
int free_all_relay_page(unsigned long *mm_arg_paddr, unsigned long *mm_arg_size);
uintptr_t change_relay_page_ownership(unsigned long relay_page_addr, unsigned long relay_page_size, char *enclave_name);

// Get enclave id
uintptr_t get_enclave_id(uintptr_t* regs);

#define ENTRY_PER_METADATA_REGION 100
#define ENTRY_PER_RELAY_PAGE_REGION 20

struct relay_page_entry_t
{
  char enclave_name[NAME_LEN];
  unsigned long  addr;
  unsigned long size;
};

// #define PROFILE_MONITOR

static inline unsigned long rdcycle(void)
{
	unsigned long ret;
  	asm volatile ("rdcycle %0" : "=r"(ret));
    return ret;
}

#endif /* _ENCLAVE_H */
