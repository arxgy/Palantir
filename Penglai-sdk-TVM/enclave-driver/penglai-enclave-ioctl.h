#ifndef _PENGLAI_ENCLAVE_IOCTL
#define _PENGLAI_ENCLAVE_IOCTL
#include <linux/uaccess.h>
#include <linux/types.h>
#include <asm/timex.h>
#include <linux/types.h>
#include "penglai-enclave.h"
#include "penglai-shm.h"

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

#define DEFAULT_CLOCK_DELAY 100000
#define DEFAULT_UNTRUSTED_PTR   0x0000001000000000
#define DEFAULT_UNTRUSTED_SIZE  8192 // 8 KB
#define DEFAULT_MAGIC_NUMBER 0xffff

#define MD_SIZE 64
#define SIGNATURE_SIZE 64
#define MAX_ELF_SIZE 512*1024*1024
#define MAX_STACK_SIZE 64*1024*1024
#define MAX_UNTRUSTED_MEM_SIZE 16*1024*1024
#define HASH_SIZE              32

#define DEFAULT_FREE_ENCLAVE -10
#define DEFAULT_DESTROY_ENCLAVE -20

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
};

struct penglai_enclave_sbi_param
{
  unsigned int * eid_ptr;
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
};

typedef struct penglai_enclave_run_sbi_param
{
  unsigned long mm_arg_addr;
  unsigned long mm_arg_size;
};

struct penglai_enclave_instance_sbi_param
{
  unsigned long sptbr;
  unsigned long free_page;
  unsigned long size;
  unsigned int* eid_ptr;

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
};

//TODO: 64?
#define PRIVATE_KEY_SIZE       32
//TODO: 32?
#define PUBLIC_KEY_SIZE        64
#define HASH_SIZE              32
#define SIGNATURE_SIZE         64

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

struct penglai_enclave_attest_param
{
  int eid;
  int isShadow;
  uintptr_t nonce;
  struct report_t report;
};

long penglai_enclave_ioctl(struct file* filep, unsigned int cmd, unsigned long args);

#endif
