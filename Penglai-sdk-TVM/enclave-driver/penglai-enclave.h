#ifndef _PENGLAI_ENCLAVE
#define _PENGLAI_ENCLAVE
#include "penglai-enclave-page.h"
#include "penglai-enclave-elfloader.h"

#define ENCLAVE_IDR_MIN 0x1000
#define ENCLAVE_IDR_MAX 0xffff

#define EXTRA_PAGES 15
#define STACK_POINT 0x0000003800000000UL
#define PENGLAI_ENCLAVE_IOC_MAGIC  0xa4

/** (#regs * sizeof(uintptr_t)) => 39*8 = 312 */
#define PENGLAI_REGS_STATE_SIZE_MAGIC 312
/* Restriction on PE's NE file length*/
#define ELF_FILE_LEN       256
/* let 0xffffffffffffffffUL be NULL slab eid */
#define NULL_EID           -1
#define DEFAULT_HEAP_VMA_MAX    72
#define DEFAULT_MMAP_VMA_MAX    72

#define INSPECT_MEM     0
#define INSPECT_REGS    1
#define INSPECT_VMA     2

extern long SBI_PENGLAI_ECALL_0(int fid);
extern long SBI_PENGLAI_ECALL_1(int fid, unsigned long arg0);
extern long SBI_PENGLAI_ECALL_2(int fid, unsigned long arg0, unsigned long arg1);
extern long SBI_PENGLAI_ECALL_3(int fid, unsigned long arg0, unsigned long arg1, unsigned long arg2);
extern long SBI_PENGLAI_ECALL_4(int fid, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3);
extern long SBI_PENGLAI_ECALL_5(int fid, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4);

#define SBI_PENGLAI_0( fid) SBI_PENGLAI_ECALL_0( fid)
#define SBI_PENGLAI_1( fid, arg0) SBI_PENGLAI_ECALL_1( fid, arg0)
#define SBI_PENGLAI_2( fid, arg0, arg1) SBI_PENGLAI_ECALL_2( fid, arg0, arg1)
#define SBI_PENGLAI_3( fid, arg0, arg1, arg2) SBI_PENGLAI_ECALL_3( fid, arg0, arg1, arg2)
#define SBI_PENGLAI_4( fid, arg0, arg1, arg2, arg3) SBI_PENGLAI_ECALL_4( fid, arg0, arg1, arg2, arg3)
#define SBI_PENGLAI_5( fid, arg0, arg1, arg2, arg3, arg4) SBI_PENGLAI_ECALL_5( fid, arg0, arg1, arg2, arg3, arg4)

//SBI CALL NUMBERS
#define SBI_SM_INIT                     100
#define SBI_SM_CREATE_ENCLAVE            99
#define SBI_SM_ATTEST_ENCLAVE            98
#define SBI_SM_RUN_ENCLAVE               97
#define SBI_SM_STOP_ENCLAVE              96
#define SBI_SM_RESUME_ENCLAVE            95
#define SBI_SM_DESTROY_ENCLAVE           94
#define SBI_SM_ALLOC_ENCLAVE_MEM         93
#define SBI_SM_MEMORY_EXTEND             92
#define SBI_SM_FREE_ENCLAVE_MEM          91
#define SBI_SM_CREATE_SERVER_ENCLAVE     90
#define SBI_SM_DESTROY_SERVER_ENCLAVE    89
#define SBI_SM_DEBUG_PRINT               88
#define SBI_SM_RUN_SHADOW_ENCLAVE        87
#define SBI_SM_CREATE_SHADOW_ENCLAVE     86
#define SBI_SM_SCHRODINGER_INIT          85
#define SBI_SM_PT_AREA_SEPARATION        83
#define SBI_SM_SPLIT_HUGE_PAGE           82
#define SBI_SM_MAP_PTE                   81
#define SBI_SM_ATTEST_SHADOW_ENCLAVE     80
#define SBI_SM_DESTROY_SHADOW_ENCLAVE    79

#define SBI_SM_RESPONSE_ENCLAVE          72
#define SBI_SM_INSPECT_ENCLAVE           70
//Error codes of SBI_SM_ALLOC_ENCLAVE_MEM
#define ENCLAVE_ATTESTATION         -3
#define ENCLAVE_NO_MEM                   -2
#define ENCLAVE_UNKNOWN_ERROR            -1
#define ENCLAVE_SUCCESS                   0
#define ENCLAVE_TIMER_IRQ                 1
#define ENCLAVE_OCALL                     2
#define ENCLAVE_YIELD                     3
#define ENCLAVE_RETURN_USER_MODE          4
#define ENCLAVE_RETURN_MONITOR_MODE       5
#define ENCLAVE_NE_REQUEST		            7

#define RETURN_USER_EXIT_ENCL             0
#define RETURN_USER_RELAY_PAGE            1
/* support NE IRQ scheduling */
#define RETURN_USER_NE_IRQ                2
#define RETURN_USER_NE_REQUEST            3

#define NE_REQUEST_INSPECT                10
#define NE_REQUEST_SHARE_PAGE             11
#define NE_REQUEST_ACQUIRE_PAGE           12
#define NE_REQUEST_REWIND									13

#define NE_REQUEST_DEBUG_PRINT            20

/* OCALL codes */
#define OCALL_MMAP                        1
#define OCALL_UNMAP                       2
#define OCALL_SYS_WRITE                   3
#define OCALL_SBRK                        4
#define OCALL_READ_SECT                   5
#define OCALL_WRITE_SECT                  6
#define OCALL_RETURN_RELAY_PAGE           7

/* add host-level selector support */
#define OCALL_CREATE_ENCLAVE		 16
#define OCALL_ATTEST_ENCLAVE		 17
#define OCALL_RUN_ENCLAVE		 	   18
#define OCALL_STOP_ENCLAVE		 	 19
#define OCALL_RESUME_ENCLAVE		 20
#define OCALL_DESTROY_ENCLAVE		 21
#define OCALL_INSPECT_ENCLAVE		 22
#define OCALL_PAUSE_ENCLAVE		 	 23

#define RESUME_FROM_TIMER_IRQ             0
#define RESUME_FROM_STOP                  1
#define RESUME_FROM_OCALL                 2
#define RESUME_FROM_REQUEST               3

#define FLAG_DESTROY                      0
#define DIRECT_DESTROY                    1
#define FREE_MAX_MEMORY                   2
#define FREE_SPEC_MEMORY                  3

#define PRE_EXTEND_MONITOR_MEMORY 1

#define SATP 0x180

/*Abstract for enclave */
#define ENCLAVE_DEFAULT_KBUFFER_ORDER           1
#define ENCLAVE_DEFAULT_KBUFFER_SIZE            ((1<<ENCLAVE_DEFAULT_KBUFFER_ORDER)*RISCV_PGSIZE)
#define NAME_LEN                                16
/* 64*1024 \div PAGESZ => 16 */
#define DEFAULT_STACK_PAGES 16

//The extended secure memory size for one time. 
#define DEFAULT_SECURE_PAGES_ORDER 9
#define DEFAULT_SHADOW_ENCLAVE_ORDER 9
#define DEFAULT_SHADOW_ENCLAVE_SIZE ((1<<DEFAULT_SHADOW_ENCLAVE_ORDER)*RISCV_PGSIZE)
// When monitor memory is exhausted, penglai driver needs to extend the memory held by monitor
#define DEFAULT_MEMORY_EXTEND_NUM 3

#ifndef _PENGLAI_ENCLAVE_TYPE
#define _PENGLAI_ENCLAVE_TYPE
typedef enum
{
  NORMAL_ENCLAVE = 0,
  SERVER_ENCLAVE = 1,
  SHADOW_ENCLAVE = 2, 
  PRIVIL_ENCLAVE = 3
} enclave_type_t;
#endif

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

typedef struct penglai_enclave
{
  /* Allocated by secure monitor */
  unsigned int eid;
  char name[NAME_LEN];
  enclave_type_t type;

  enclave_mem_t* enclave_mem;
  vaddr_t kbuffer;
  unsigned long kbuffer_size;
  unsigned long ocall_func_id;
  unsigned long ocall_arg0;
  unsigned long ocall_arg1;
  unsigned long ocall_syscall_num;
  unsigned long retval;
  unsigned long satp;
} enclave_t;

typedef struct penglai_enclave_instance
{
  /* Allocated by secure monitor */
  unsigned long addr;
  unsigned long order;
  unsigned long eid;
  vaddr_t kbuffer;
  unsigned long kbuffer_size;
  unsigned long ocall_func_id;
  unsigned long ocall_arg0;
  unsigned long ocall_arg1;
  unsigned long ocall_syscall_num;
  unsigned long retval;
  unsigned long satp;
}enclave_instance_t;

typedef struct require_sec_memory
{
  unsigned long size;
  unsigned long paddr;
  unsigned long resp_size;
} require_sec_memory_t;

/* This param should be sync with the struct in PE's hdr file.*/
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
  unsigned long migrate_arg;
} ocall_create_param_t;

typedef struct ocall_attest_param
{
  int attest_eid; // idr
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

enclave_t* create_enclave(int total_pages, char* name, enclave_type_t type);
int destroy_enclave(enclave_t* enclave);
unsigned int enclave_idr_alloc(enclave_t* enclave);
enclave_t* enclave_idr_remove(unsigned int ueid); 
enclave_t* get_enclave_by_id(unsigned int ueid);

unsigned int enclave_instance_idr_alloc(enclave_instance_t* enclave_instance);
enclave_instance_t* enclave_instance_idr_remove(unsigned int ueid); 
enclave_instance_t* get_enclave_instance_by_id(unsigned int ueid);

#endif
