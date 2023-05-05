#ifndef _ENCLAVE_ARGS_H
#define _ENCLAVE_ARGS_H
#include "sm/thread.h"
#define HASH_SIZE              32
#define PRIVATE_KEY_SIZE       32
#define PUBLIC_KEY_SIZE        64
#define SIGNATURE_SIZE         64

#define MANU_PUB_KEY           (void*)((unsigned long)0x801ff000)
#define DEV_PUB_KEY            (MANU_PUB_KEY + PUBLIC_KEY_SIZE)
#define DEV_PRI_KEY            (DEV_PUB_KEY + PUBLIC_KEY_SIZE)
#define SM_PUB_KEY             (DEV_PRI_KEY + PRIVATE_KEY_SIZE)
#define SM_PRI_KEY             (SM_PUB_KEY + PUBLIC_KEY_SIZE)
#define SM_HASH                (SM_PRI_KEY + PRIVATE_KEY_SIZE)
#define SM_SIGNATURE           (SM_HASH + HASH_SIZE)

struct mm_alloc_arg_t
{
  unsigned long req_size;
  uintptr_t resp_addr;
  unsigned long resp_size;
};

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

struct pt_entry_t
{
  unsigned long pte_addr;
  unsigned long pte;
};

#if __riscv_xlen == 64

#define NAME_LEN           16

typedef enum
{
  NORMAL_ENCLAVE = 0,
  SERVER_ENCLAVE = 1
} enclave_type_t;

typedef struct enclave_create_param
{
  unsigned int *eid_ptr;
  char name[NAME_LEN];
  enclave_type_t type;

  unsigned long paddr;
  unsigned long size;

  unsigned long entry_point;

  unsigned long free_mem;

  //enclave shared mem with kernel
  unsigned long kbuffer;//paddr
  unsigned long kbuffer_size;

  //enclave shared mem with host
  unsigned long shm_paddr;
  unsigned long shm_size;

  unsigned long *ecall_arg0;
  unsigned long *ecall_arg1;
  unsigned long *ecall_arg2;
  unsigned long *ecall_arg3;
  unsigned long *retval;
} enclave_create_param_t;

typedef struct enclave_run_param
{
  unsigned long mm_arg_addr;
  unsigned long mm_arg_size;
} enclave_run_param_t;

typedef struct shadow_enclave_run_param
{
  unsigned long sptbr;
  unsigned long free_page;
  unsigned long size;
  unsigned int *eid_ptr;

  unsigned long kbuffer;//paddr
  unsigned long kbuffer_size;

  unsigned long shm_paddr;
  unsigned long shm_size;

  unsigned long mm_arg_addr;
  unsigned long mm_arg_size;

  unsigned long *ecall_arg0;
  unsigned long *ecall_arg1;
  unsigned long *ecall_arg2;
  unsigned long *ecall_arg3;
  unsigned long *retval;
  char name[NAME_LEN];
} shadow_enclave_run_param_t;

#else

#define ATTRIBUTE_R               0x1
#define ATTRIBUTE_W               0x2
#define ATTRIBUTE_X               0x4
#define DEFAULT_EAPP_REGIONS_NUM             5

struct region_t {
  unsigned long base;
  unsigned long size;
  unsigned long attributes;
};

struct eapp_t {
  unsigned long offset;
  unsigned long size;
  unsigned long uuid;
  struct region_t regions[DEFAULT_EAPP_REGIONS_NUM];
};

typedef struct enclave_create_param
{
  unsigned long uuid;
  unsigned long *eid_ptr;

  unsigned long untrusted_ptr;
  unsigned long untrusted_size;
}enclave_create_param_t;

struct init_enclave_create_param_t
{
  unsigned long uuid;
  unsigned long entry_point;
  struct region_t regions[DEFAULT_EAPP_REGIONS_NUM];
};

#endif /* __riscv_xlen == 64 */

#endif /* _ENCLAVE_ARGS_H */
