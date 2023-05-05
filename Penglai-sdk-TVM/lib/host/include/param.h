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

typedef enum
{
  NORMAL_ENCLAVE = 0,
  SERVER_ENCLAVE = 1,
  SHADOW_ENCLAVE
} enclave_type_t;

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

#endif
