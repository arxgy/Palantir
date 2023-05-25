#ifndef _ENCLAVE_PARAM
#define _ENCLAVE_PARAM
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <pthread.h>
#include <string.h>

#define PENGLAI_ENCLAVE_IOC_MAGIC  0xa4
#define HASH_SIZE 32
#define DEFAULT_HEAP_VMA_MAX    72
#define DEFAULT_MMAP_VMA_MAX    72

#define INSPECT_MEM     0
#define INSPECT_REGS    1
#define INSPECT_VMA     2

#define PENGLAI_ENCLAVE_IOC_CREATE_ENCLAVE \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x00, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_RUN_ENCLAVE \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x01, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_ATTEST_ENCLAVE \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x02, struct penglai_enclave_attest_param)
#define PENGLAI_ENCLAVE_IOC_STOP_ENCLAVE \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x03, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_RESUME_ENCLAVE \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x04, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_DESTROY_ENCLAVE \
  _IOW(PENGLAI_ENCLAVE_IOC_MAGIC, 0x05, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_DEBUG_PRINT \
  _IOW(PENGLAI_ENCLAVE_IOC_MAGIC, 0x06, struct penglai_enclave_user_param)

#define PENGLAI_SHMGET \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x10, struct penglai_shmget_param)
#define PENGLAI_SHMAT \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x11, struct penglai_shmat_param)
#define PENGLAI_SHMDT \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x12, struct penglai_shmdt_param)
#define PENGLAI_SHMCTL \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x13, struct penglai_shmctl_param)

#define PENGLAI_SCHRODINGER_GET \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x14, struct penglai_schrodinger_get_param)
#define PENGLAI_SCHRODINGER_AT \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x15, struct penglai_schrodinger_at_param)
#define PENGLAI_SCHRODINGER_DT \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x16, struct penglai_schrodinger_dt_param)
#define PENGLAI_SCHRODINGER_CTL \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x17, struct penglai_schrodinger_ctl_param)

#define PENGLAI_PERSISTENCY_INIT \
  _IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x18, int)

#define DEFAULT_STACK_SIZE      64*1024// 64 kB
#define DEFAULT_UNTRUSTED_PTR   0x0000001000000000
#define DEFAULT_UNTRUSTED_SIZE  8192 // 8 KB

#define NAME_LEN                16
#define PRIVATE_KEY_SIZE       32
#define PUBLIC_KEY_SIZE        64
#define HASH_SIZE              32
#define SIGNATURE_SIZE         64

#define ELF_FILE_LEN           256
/* 64*1024 \div PAGESZ => 16 */
#define DEFAULT_STACK_PAGES 16

struct sm_report_t
{
  unsigned char hash[HASH_SIZE];
  unsigned char signature[SIGNATURE_SIZE];
  unsigned char sm_pub_key[PUBLIC_KEY_SIZE];
};

struct enclave_report_t
{
  unsigned char hash[HASH_SIZE];
  unsigned char signature[SIGNATURE_SIZE];
  uintptr_t nonce;
};

struct report_t
{
  struct sm_report_t sm;
  struct enclave_report_t enclave;
  unsigned char dev_pub_key[PUBLIC_KEY_SIZE];
};

struct signature_t
{
  unsigned char r[PUBLIC_KEY_SIZE/2];
  unsigned char s[PUBLIC_KEY_SIZE/2];
};

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

struct penglai_enclave_user_param
{
  unsigned long eid;
  char name[NAME_LEN];
  enclave_type_t type;
  unsigned long elf_ptr;
  long elf_size;
  long stack_size;
  int shmid;
  int isShadow;
  unsigned long shm_offset;
  unsigned long shm_size;
  int schrodinger_id;
  int rerun_reason;
  unsigned long schrodinger_offset;
  unsigned long schrodinger_size;
  unsigned long retval;
  char elf_file_name[ELF_FILE_LEN];
};

struct penglai_shmget_param
{
  int key;
  unsigned long size;
  int shmflg;
};

struct penglai_shmat_param
{
  int shmid;
  void* shmaddr;
  unsigned long size;
  int shmflg;
};

struct penglai_shmdt_param
{
  int shmid;
  void* shmaddr;
  unsigned long size;
};

struct penglai_shmctl_param
{
  int shmid;
};

struct penglai_schrodinger_get_param
{
  int key;
  unsigned long size;
  int flg;
};

struct penglai_schrodinger_at_param
{
  int id;
  void* addr;
  unsigned long size;
  int flg;
};

struct penglai_schrodinger_dt_param
{
  int id;
  void* addr;
  unsigned long size;
};

struct penglai_schrodinger_ctl_param
{
  int id;
};

struct penglai_enclave_attest_param
{
  int eid;
  int isShadow;
  uintptr_t nonce;
  struct report_t report;
};

struct enclave_args
{
  char name[NAME_LEN];
  enclave_type_t type;
  unsigned long stack_size;
  int shmid;
  unsigned long shm_offset;
  unsigned long shm_size;
};

void enclave_args_init(struct enclave_args* enclave_args);

typedef unsigned char byte;

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
  snapshot_mmap_state_t mmap;
  snapshot_heap_state_t heap;
} snapshot_state_t;

#endif
