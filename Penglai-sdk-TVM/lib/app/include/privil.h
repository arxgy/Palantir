#ifndef _EAPP_PRIVIL_OCALL
#define _EAPP_PRIVIL_OCALL

#define PAGE_SIZE 4096

#define NAME_LEN        16
#define ELF_FILE_LEN    256

#define RETURN_USER_EXIT_ENCL             0
#define RETURN_USER_RELAY_PAGE            1
#define RETURN_USER_NE_IRQ                2
#define RETURN_USER_NE_REQUEST            3

#define NE_REQUEST_INSPECT                10
#define NE_REQUEST_SHARE_PAGE             11
#define NE_REQUEST_ACQUIRE_PAGE           12

#define NE_REQUEST_DEBUG_PRINT            20

#define DEFAULT_HEAP_VMA_MAX    72
#define DEFAULT_MMAP_VMA_MAX    72

#define INSPECT_MEM     0
#define INSPECT_REGS    1
#define INSPECT_VMA     2

/* 64*1024 \div PAGESZ => 16 */
#define DEFAULT_STACK_PAGES 16
/* todo: host-level update */
typedef enum
{
  NORMAL_ENCLAVE = 0,
  SERVER_ENCLAVE = 1,
  SHADOW_ENCLAVE = 2, 
  PRIVIL_ENCLAVE = 3
} enclave_type_t;

struct ocall_general_regs_t
{
  unsigned long slot;
  unsigned long ra;
  unsigned long sp;
  unsigned long gp;
  unsigned long tp;
  unsigned long t0;
  unsigned long t1;
  unsigned long t2;
  unsigned long s0;
  unsigned long s1;
  unsigned long a0;
  unsigned long a1;
  unsigned long a2;
  unsigned long a3;
  unsigned long a4;
  unsigned long a5;
  unsigned long a6;
  unsigned long a7;
  unsigned long s2;
  unsigned long s3;
  unsigned long s4;
  unsigned long s5;
  unsigned long s6;
  unsigned long s7;
  unsigned long s8;
  unsigned long s9;
  unsigned long s10;
  unsigned long s11;
  unsigned long t3;
  unsigned long t4;
  unsigned long t5;
  unsigned long t6;
};

/* app-level PE create enclave param */
typedef struct ocall_create_param
{
  /* enclave */
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
  unsigned long end;    // VA in NE
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
 * \param stack_sz #page of stack
 * \param stack is VA in PE, contains stack pages in NE 
 *        ([0] means highest page)
 *        stack[0]: [STACK_BASE -   PAGESZ] to [STACK_BASE]
 *        stack[1]: [STACK_BASE - 2*PAGESZ] to [STACK_BASE - PAGESZ]
 *        ...
 * \param mmap stores all mmap vma and its contents (VA in PE)
 * \param heap stores all heap vma and its contents (VA in PE)
*/
typedef struct snapshot_state
{
  ocall_request_dump_t regs;
  unsigned long stack_sz;
  unsigned long stack[DEFAULT_STACK_PAGES];  
  snapshot_mmap_state_t mmap;
  snapshot_heap_state_t heap;
} snapshot_state_t;

#endif