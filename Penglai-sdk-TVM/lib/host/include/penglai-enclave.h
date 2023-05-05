#ifndef _PL_ENCLAVE
#define _PL_ENCLAVE
#include "elf.h"
#include "param.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdarg.h>

#define PENGLAI_ENCLAVE_DEV_PATH "/dev/penglai_enclave_dev"

#define RETURN_USER_EXIT_ENCL             0
#define RETURN_USER_RELAY_PAGE            1

struct PLenclave
{
  struct elf_args *elffile;
  int eid;
  int fd;
  struct penglai_enclave_user_param user_param;
  struct penglai_enclave_attest_param attest_param;
};

int PLenclave_init(struct PLenclave *PLenclave);
int PLenclave_create(struct PLenclave* PLenclave, struct elf_args* u_elffile, struct enclave_args* u_param);
int PLenclave_run(struct PLenclave *PLenclave);
int PLenclave_attest(struct PLenclave *PLenclave, uintptr_t nonce);
int PLenclave_stop(struct PLenclave *PLenclave);
int PLenclave_resume(struct PLenclave *PLenclave);
int PLenclave_destroy(struct PLenclave *PLenclave);
int PLenclave_destruct(struct PLenclave *PLenclave);

int PLenclave_shmget(unsigned long size);
void* PLenclave_shmat(int shmid, void* addr);
int PLenclave_shmdt(int shmid, void* addr);
int PLenclave_shmctl(int shmid);

int PLenclave_set_mem_arg(struct PLenclave* enclave, int id, unsigned long offset, unsigned long size);
int PLenclave_set_shm(struct PLenclave* enclave, int shmid, unsigned long offset, unsigned long size);
int PLenclave_set_rerun_arg(struct PLenclave *enclave, int rerun_reason);
int PLenclave_schrodinger_get(unsigned long size);
void* PLenclave_schrodinger_at(int id, void* addr);
int PLenclave_schrodinger_dt(int id, void* addr);
int PLenclave_schrodinger_ctl(int id);
int PLenclave_fs_persistency_init(int shm_id);

#endif
