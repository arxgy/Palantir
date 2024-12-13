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
#define ENCLAVES_PER_GLOBAL_VAR_REGION 10
#define ENCLAVE_METADATA_REGION_SIZE ((sizeof(struct enclave_t)) * ENCLAVES_PER_METADATA_REGION)
#define SHADOW_ENCLAVE_METADATA_REGION_SIZE ((sizeof(struct shadow_enclave_t)) * ENCLAVES_PER_METADATA_REGION)
#define RELAY_PAGE_NUM 10
#define MAX_HARTS 8
#define ENCLAVE_MODE 1
#define NORMAL_MODE 0
/* 64*1024 \div PAGESZ => 16 */
#define DEFAULT_STACK_PAGES 16

#define CHILDREN_METADATA_REGION_SIZE  ((sizeof(struct children_enclave_t)) * ENCLAVES_PER_METADATA_REGION)
#define BSS_SECTION_METADATA_REGION_SIZE  ((sizeof(bss_region_t)) * ENCLAVES_PER_GLOBAL_VAR_REGION)
#define DATA_SECTION_METADATA_REGION_SIZE  ((sizeof(data_region_t)) * ENCLAVES_PER_GLOBAL_VAR_REGION)

//FIXME: need to determine the suitable threshold depending on the performance.
#define ENCLAVE_SELF_HASH_THRESHOLD  (RISCV_PGSIZE)

//FIXME: entry point of self hash code, may need to change for some unknown reasons.
#define ENCLAVE_SELF_HASH_ENTRY  (0x8000)
#define STACK_POINT 0x0000003800000000UL

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
  enclave->type = ((struct_type)create_args)->type; \
  enclave->state = FRESH; \
  enclave->caller_eid = -1; \
  enclave->top_caller_eid = -1; \
  enclave->cur_callee_eid = -1; \
  enclave->ocalling_shm_key = 0; \
  sbi_memcpy(enclave->enclave_name, ((struct_type)create_args)->name, NAME_LEN); \
  enclave->parent_eid = ((struct_type)create_args)->create_caller_eid; \
  enclave->children_metadata_head = NULL; \
  enclave->children_metadata_tail = NULL; \
  enclave->data_record_head = NULL; \
  enclave->bss_record_head = NULL; \
  enclave->data_record_len = 0; \
  enclave->bss_record_len = 0; \
} while(0)


#define SET_SHADOW_ENCLAVE_METADATA(point, enclave, create_args, struct_type, base) do { \
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
  enclave->parent_eid = ((struct_type)create_args)->create_caller_eid; \
  enclave->children_metadata_head = NULL; \
  enclave->children_metadata_tail = NULL; \
  enclave->data_record_head = NULL; \
  enclave->bss_record_head = NULL; \
  enclave->data_record_len = 0; \
  enclave->bss_record_len = 0; \
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
  /* parent info */
  unsigned long parent_eid;
  struct link_mem_t *children_metadata_head;
  struct link_mem_t *children_metadata_tail;
  /* global variable info */
  struct link_mem_t *data_record_head;
  unsigned long data_record_len;
  struct link_mem_t *bss_record_head;
  unsigned long bss_record_len;
};

/* 
  entry for children enclave's messages 
  now only support eid for indexing & state for slab 
    provided by Anonymous Author @ May 10, 2023.
*/
struct children_enclave_t
{
  /* we only use VALID & FRESH */
  enclave_state_t state;
  unsigned int eid;
};

typedef struct penglai_data_records
{
  unsigned long sect_vaddr;
  unsigned long sect_size;
  unsigned long sect_content; // pa addr to the section contents.
  unsigned long next_record;  // pa addr to next record
  unsigned long next_record_pa;	// pa addr to next
} elf_data_records_t;

// todo: support merge (continuous address)
typedef struct penglai_bss_records
{
  unsigned long sect_size;
  unsigned long sect_vaddr;
  unsigned long next_record; // va addr to next record
  unsigned long next_record_pa;	// pa addr to next record
} elf_bss_records_t;

typedef struct bss_region
{
  unsigned long vaddr;
  unsigned long size;
} bss_region_t;

typedef struct data_region
{
  unsigned long vaddr;
  unsigned long data; // paddr of data contents
  unsigned long size;
} data_region_t;



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

int distant_parent(uintptr_t child_eid, uintptr_t parent_eid);
// Called by host
// Enclave-related operations
uintptr_t create_enclave(enclave_create_param_t create_args);
uintptr_t attest_enclave(uintptr_t eid, uintptr_t report, uintptr_t nonce);
uintptr_t run_enclave(uintptr_t* regs, unsigned int eid, enclave_run_param_t enclave_run_param);
uintptr_t stop_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t wake_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t destroy_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t inspect_enclave(uintptr_t tgt_eid, uintptr_t src_eid, uintptr_t dump_context, uintptr_t inspect_addr, uintptr_t inspect_size);
uintptr_t response_enclave(uintptr_t tgt_eid, uintptr_t src_eid, uintptr_t response_arg);
uintptr_t memory_layout_dump(uintptr_t tgt_eid, uintptr_t src_eid);

// Shadow encalve related operations
uintptr_t create_shadow_enclave(enclave_create_param_t create_args);
uintptr_t attest_shadow_enclave(uintptr_t eid, uintptr_t report, uintptr_t nonce);
uintptr_t destroy_shadow_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t run_shadow_enclave(uintptr_t* regs, unsigned int eid, shadow_enclave_run_param_t enclave_run_param);

// Resume enclave
uintptr_t resume_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t resume_from_ocall(uintptr_t* regs, unsigned int eid);
uintptr_t resume_from_request(uintptr_t* regs, unsigned int eid);


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

/**
 * Ocall transition functions
*/
uintptr_t privil_create_enclave(uintptr_t* regs, uintptr_t enclave_create_args);
uintptr_t privil_attest_enclave(uintptr_t* regs, uintptr_t enclave_attest_args);
uintptr_t privil_run_enclave(uintptr_t* regs, uintptr_t enclave_run_args);
uintptr_t privil_stop_enclave(uintptr_t* regs, uintptr_t eid);
uintptr_t privil_resume_enclave(uintptr_t* regs, uintptr_t enclave_resume_args);
uintptr_t privil_destroy_enclave(uintptr_t* regs, uintptr_t enclave_destroy_args);
uintptr_t privil_inspect_enclave(uintptr_t* regs, uintptr_t enclave_inspect_args);
uintptr_t privil_pause_enclave(uintptr_t* regs, uintptr_t enclave_pause_args);

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

struct ocall_general_regs_t
{
  uintptr_t slot;
  uintptr_t ra;
  uintptr_t sp;
  uintptr_t gp;
  uintptr_t tp;
  uintptr_t t0;
  uintptr_t t1;
  uintptr_t t2;
  uintptr_t s0;
  uintptr_t s1;
  uintptr_t a0;
  uintptr_t a1;
  uintptr_t a2;
  uintptr_t a3;
  uintptr_t a4;
  uintptr_t a5;
  uintptr_t a6;
  uintptr_t a7;
  uintptr_t s2;
  uintptr_t s3;
  uintptr_t s4;
  uintptr_t s5;
  uintptr_t s6;
  uintptr_t s7;
  uintptr_t s8;
  uintptr_t s9;
  uintptr_t s10;
  uintptr_t s11;
  uintptr_t t3;
  uintptr_t t4;
  uintptr_t t5;
  uintptr_t t6;
};

/* sm-level OCall param */
typedef struct ocall_create_param
{
  /* allocated enclave */
  /* inner layer eid */
  unsigned int eid;
  
  /* enclaveFile */
  unsigned long elf_file_size;
  unsigned long elf_file_ptr; // VA from enclave
  /* params */
  char encl_name [NAME_LEN];
  enclave_type_t encl_type;
  unsigned long stack_size;
  int shmid;
  unsigned long shm_offset;
  unsigned long shm_size;
  char elf_file_name [ELF_FILE_LEN];
  unsigned long migrate_arg;
} ocall_create_param_t;

typedef struct ocall_attest_param
{
  int attest_eid;
  int current_eid;
  int isShadow;
  unsigned long nonce;
  unsigned long report_ptr; // VA
} ocall_attest_param_t;

/* used in RUN & RESUME */
typedef struct ocall_run_param
{
  int run_eid;
  int resume_reason;  // let sdk read (RDONLY), sync with *reason_ptr.
  unsigned long reason_ptr;
  unsigned long retval_ptr;
  unsigned long request_reason;  // NE_REQUEST_INSPECT, NE_REQUEST_SHARE_PAGE, ...
  unsigned long request_arg;     // VA in PE, accept parameters from NE.
  unsigned long response_arg;    // VA in PE, send parameters to NE.
} ocall_run_param_t;

typedef struct vm_area_dump
{
  unsigned long va_start;
  unsigned long va_end;
} vm_area_dump_t;

typedef struct enclave_mem_dump
{
  vm_area_dump_t text_vma;
  vm_area_dump_t stack_vma;
  unsigned long heap_sz;
  unsigned long mmap_sz;
  vm_area_dump_t heap_vma[DEFAULT_HEAP_VMA_MAX];
  vm_area_dump_t mmap_vma[DEFAULT_MMAP_VMA_MAX];
} enclave_mem_dump_t;

typedef struct ocall_destroy_param
{
  int destroy_eid;
  unsigned long op;
  unsigned long dump_arg;  // VA in PE;
} ocall_destroy_param_t;

typedef struct ocall_inspect_param
{
  int inspect_eid;
  int dump_context;
  unsigned long inspect_address; // VA in NE
  unsigned long inspect_size;
  int reason;  // let sdk read (RDONLY), sync with *reason_ptr.
  unsigned long reason_ptr;
  unsigned long inspect_result; // VA in PE
} ocall_inspect_param_t;

typedef struct ocall_request
{
  unsigned long request;            // reason in PE
  unsigned long inspect_request;    // VA in NE
  unsigned long share_page_request; // VA in NE
  unsigned long rewind_request;     // VA in NE
  /* todo. support more requests */
} ocall_request_t;

typedef struct ocall_response
{
  unsigned long request;              // reason in PE, similar with ocall_request_t. 0 means do nothing.
  unsigned long inspect_response;     // VA in NE
  unsigned long share_page_response;  // VA in NE
} ocall_response_t;

typedef struct ocall_request_inspect
{
    unsigned long inspect_ptr;
    unsigned long inspect_size;
} ocall_request_inspect_t;

typedef struct ocall_request_dump 
{ 
  unsigned long encl_ptbr;
  unsigned long stvec;
  unsigned long mie;
  unsigned long mideleg;
  unsigned long medeleg;
  unsigned long mepc;
  unsigned long cache_binding;
  struct ocall_general_regs_t state;
} ocall_request_dump_t;

/**
 * Used by both sharer and sharee.
 * For sharer, eid & share_id will be neglected and auto-filled by PE.
 * For sharee, eid & share_id is required to specify which page that sharee needs.
*/
typedef struct ocall_request_share
{
  unsigned long eid;
  unsigned long share_id;
  unsigned long share_content_ptr;  // VA
  unsigned long share_size;
} ocall_request_share_t;

typedef struct ocall_request_rewind
{
  unsigned long pma;                // paddr
} ocall_request_rewind_t;

typedef struct ocall_response_share
{
  unsigned long src_ptr;  // VA in PE
  unsigned long dest_ptr; // VA in NE
  unsigned long share_size;
} ocall_response_share_t;

typedef struct snapshot_mem_area
{
  unsigned long vaddr;  // VA in PE
  unsigned long start;  // VA in NE
  unsigned long paddr;  // alloc by kernel
} snapshot_mem_area_t;

typedef struct snapshot_mmap_state
{
  unsigned long mmap_sz;
  snapshot_mem_area_t mmap_areas[DEFAULT_MMAP_VMA_MAX];
} snapshot_mmap_state_t;

typedef struct snapshot_heap_state
{
  unsigned long heap_sz;
  snapshot_mem_area_t heap_areas[DEFAULT_HEAP_VMA_MAX];
} snapshot_heap_state_t;

/**
 *  We use this parameter to migrate enclave. 
 * \param regs is runtime register state of NE
 * \param stack is VA in PE, contains stack pages in NE 
 *        ([0] means highest page)
 * \param mmap stores all mmap vma and its contents (VA in PE)
 * \param heap stores all heap vma and its contents (VA in PE)
*/
typedef struct snapshot_state
{
  ocall_request_dump_t regs;
  unsigned long stack_sz;
  unsigned long stack[DEFAULT_STACK_PAGES];  
  unsigned long stack_pa[DEFAULT_STACK_PAGES];
  snapshot_mmap_state_t mmap;
  snapshot_heap_state_t heap;
} snapshot_state_t;

#endif /* _ENCLAVE_H */
