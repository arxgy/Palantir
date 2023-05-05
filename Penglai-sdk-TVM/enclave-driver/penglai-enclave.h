#ifndef _PENGLAI_ENCLAVE
#define _PENGLAI_ENCLAVE
#include "penglai-enclave-page.h"
#include "penglai-enclave-elfloader.h"

#define ENCLAVE_IDR_MIN 0x1000
#define ENCLAVE_IDR_MAX 0xffff

#define EXTRA_PAGES 15
#define STACK_POINT 0x0000003800000000UL
#define PENGLAI_ENCLAVE_IOC_MAGIC  0xa4

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

#define RETURN_USER_EXIT_ENCL             0
#define RETURN_USER_RELAY_PAGE            1

/* OCALL codes */
#define OCALL_MMAP                        1
#define OCALL_UNMAP                       2
#define OCALL_SYS_WRITE                   3
#define OCALL_SBRK                        4
#define OCALL_READ_SECT                   5
#define OCALL_WRITE_SECT                  6
#define OCALL_RETURN_RELAY_PAGE           7

#define RESUME_FROM_TIMER_IRQ             0
#define RESUME_FROM_STOP                  1
#define RESUME_FROM_OCALL                 2

#define FLAG_DESTROY                      0
#define DIRECT_DESTROY                    1
#define FREE_MAX_MEMORY                   2
#define FREE_SPEC_MEMORY                  3

#define PRE_EXTEND_MONITOR_MEMORY 1

#define SATP 0x180

/*Abstract for enclave */
#define ENCLAVE_DEFAULT_KBUFFER_ORDER           0
#define ENCLAVE_DEFAULT_KBUFFER_SIZE            ((1<<ENCLAVE_DEFAULT_KBUFFER_ORDER)*RISCV_PGSIZE)
#define NAME_LEN                                16

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
  SHADOW_ENCLAVE
} enclave_type_t;
#endif

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

enclave_t* create_enclave(int total_pages, char* name, enclave_type_t type);
int destroy_enclave(enclave_t* enclave);
unsigned int enclave_idr_alloc(enclave_t* enclave);
enclave_t* enclave_idr_remove(unsigned int ueid); 
enclave_t* get_enclave_by_id(unsigned int ueid);

unsigned int enclave_instance_idr_alloc(enclave_instance_t* enclave_instance);
enclave_instance_t* enclave_instance_idr_remove(unsigned int ueid); 
enclave_instance_t* get_enclave_instance_by_id(unsigned int ueid);

#endif
