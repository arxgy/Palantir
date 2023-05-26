#include "penglai-enclave.h"
#include <sys/mman.h>

int PLenclave_shmget(unsigned long size)
{
  int fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(fd < 0)
  {
    printf("PLenclave_shmget: failed to open enclave dev\n");
    return -1;
  }

  struct penglai_shmget_param param;
  param.key = 0;
  param.size = size;
  param.shmflg = 0;
  int ret = ioctl(fd, PENGLAI_SHMGET, &param);
  if(ret < 0)
  {
    printf("PLenclave_shmget: failed to create shm\n");
  }

  close(fd);
  return ret;
}

void* PLenclave_shmat(int shmid, void* addr)
{
  void* ret = NULL;

  int fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(fd < 0)
  {
    printf("PLenclave_shmat: failed to open enclave dev\n");
    return (void*)-1;
  }

  struct penglai_shmat_param param;
  param.shmid = shmid;
  param.shmaddr = addr;
  param.shmflg = 0;
  int bind = ioctl(fd, PENGLAI_SHMAT, &param);
  if(bind < 0)
  {
    printf("PLenclave_shmat: failed to bind shm %d\n", shmid);
    ret = (void*)-1;
    goto out;
  }
  ret = mmap(addr, param.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if(ret == (void*)-1)
  {
    printf("PLenclave_shmat: failed to mmap shm %d\n", shmid);
  }

out:
  close(fd);
  return ret;
}

int PLenclave_shmdt(int shmid, void* addr)
{
  int fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(fd < 0)
  {
    printf("PLenclave_shmdt: failed to open enclave dev\n");
    return -1;
  }

  struct penglai_shmdt_param param;
  param.shmid = shmid;
  param.shmaddr = addr;
  int ret = ioctl(fd, PENGLAI_SHMDT, &param);
  if(ret < 0)
  {
    printf("PLenclave_shmdt: failed to unbind shm%d\n", shmid);
    ret = -1;
    goto out;
  }

  ret = munmap(addr, param.size);
  if(ret < 0)
  {
    printf("PLenclave_shmdt: failed to unmap shm%d\n", shmid);
    ret = -1;
  }

out:
  close(fd);
  return ret;
}

int PLenclave_shmctl(int shmid)
{
  int fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(fd < 0)
  {
    printf("PLenclave_shmctl: failed to open enclave dev\n");
    return -1;
  }

  struct penglai_shmctl_param param;
  param.shmid = shmid;
  int ret = ioctl(fd, PENGLAI_SHMCTL, &param);
  if(ret < 0)
  {
    printf("PLenclave_shmctl: failed to destroy shm%d\n", shmid);
    ret = -1;
  }

  close(fd);
  return 0;
}

int PLenclave_schrodinger_get(unsigned long size)
{
  int fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(fd < 0)
  {
    printf("PLenclave_schrodinger_get: failed to open enclave dev\n");
    return -1;
  }

  struct penglai_schrodinger_get_param param;
  param.key = 0;
  param.size = size;
  param.flg = 0;
  int ret = ioctl(fd, PENGLAI_SCHRODINGER_GET, &param);
  if(ret < 0)
  {
    printf("PLenclave_schrodinger_get: failed to create\n");
  }

  close(fd);
  return ret;
}

void* PLenclave_schrodinger_at(int id, void* addr)
{
  void* ret = NULL;

  int fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(fd < 0)
  {
    printf("PLenclave_schrodinger_at: failed to open enclave dev\n");
    return (void*)-1;
  }

  struct penglai_schrodinger_at_param param;
  param.id = id;
  param.addr = addr;
  param.flg = 0;
  int bind = ioctl(fd, PENGLAI_SCHRODINGER_AT, &param);
  if(bind < 0)
  { 
    printf("PLenclave_schrodinger_at: failed to bind schrodinger mm %d\n", id);
    ret = (void*)-1;
    goto out;
  }
  // map the schrodinger for currenr thread
  ret = mmap(addr, param.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if(ret == (void*)-1)
  {
    printf("PLenclave_schrodinger_at: failed to mmap schrodinger mm %d\n", id);
  }

out:
  close(fd);
  return ret;
}

int PLenclave_schrodinger_dt(int id, void* addr)
{
  int fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(fd < 0)
  {
    printf("PLenclave_schrodinger_dt: failed to open enclave dev\n");
    return -1;
  }

  struct penglai_schrodinger_dt_param param;
  param.id = id;
  param.addr = addr;
  int ret = ioctl(fd, PENGLAI_SCHRODINGER_DT, &param);
  if(ret < 0)
  {
    printf("PLenclave_schrodinger_dt: failed to unbind schrodinger mm%d\n", id);
    ret = -1;
    goto out;
  }

  ret = munmap(addr, param.size);
  if(ret < 0)
  {
    printf("PLenclave_schrodinger_dt: failed to unmap schrodinger mm%d\n", id);
    ret = -1;
  }

out:
  close(fd);
  return ret;
}

int PLenclave_schrodinger_ctl(int id)
{
  int fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(fd < 0)
  {
    printf("PLenclave_schrodinger_ctl: failed to open enclave dev\n");
    return -1;
  }

  struct penglai_schrodinger_ctl_param param;
  param.id = id;
  int ret = ioctl(fd, PENGLAI_SCHRODINGER_CTL, &param);
  if(ret < 0)
  {
    printf("PLenclave_schrodinger_ctl: failed to destroy schrodinger mm%d\n", id);
    ret = -1;
  }

  close(fd);
  return 0;
}

int PLenclave_set_shm(struct PLenclave *enclave, int shmid, uintptr_t offset, uintptr_t size)
{
  if(!enclave)
    return -1;

  enclave->user_param.shmid = shmid;
  enclave->user_param.shm_offset = offset;
  enclave->user_param.shm_size = size;

  return 0;
}

int PLenclave_set_mem_arg(struct PLenclave *enclave, int id, uintptr_t offset, uintptr_t size)
{
  if(!enclave)
    return -1;

  enclave->user_param.schrodinger_id = id;
  enclave->user_param.schrodinger_offset = offset;
  enclave->user_param.schrodinger_size = size;

  return 0;
}

int PLenclave_set_rerun_arg(struct PLenclave *enclave, int rerun_reason)
{
  if(!enclave)
    return -1;

  enclave->user_param.rerun_reason = rerun_reason;
  return 0;
}

int PLenclave_init(struct PLenclave *enclave)
{
  if(!enclave)
    return -1;

  memset(enclave, 0, sizeof(struct PLenclave));
  enclave->elffile = NULL;
  enclave->eid = -1;
  enclave->fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(enclave->fd < 0)
  {
    fprintf(stderr, "LIB: PLenclave_init: cannot open enclave dev\n");
    return -1;
  }

  return 0;
}

int PLenclave_create(struct PLenclave* PLenclave, struct elf_args* u_elffile, struct enclave_args* u_param)
{
  int ret = 0;

  if(PLenclave->fd < 0)
  {
    fprintf(stderr,"LIB: PLenclave_create: enclave hasn't be initialized yet\n");
    return -1;
  }

  if(!u_elffile)
  {
    fprintf(stderr,"LIB: PLenclave_create: elffile does not exist\n");
    return -1;
  }

  PLenclave->elffile = u_elffile;
  PLenclave->user_param.elf_ptr = (unsigned long)(u_elffile->ptr);
  PLenclave->user_param.elf_size = u_elffile->size;
  PLenclave->user_param.stack_size = u_param->stack_size;
  if(u_param->type == SHADOW_ENCLAVE)
    PLenclave->user_param.stack_size = 0;
  PLenclave->user_param.shmid = u_param->shmid;
  PLenclave->user_param.shm_offset = u_param->shm_offset;
  PLenclave->user_param.shm_size = u_param->shm_size;
  PLenclave->user_param.type = u_param->type;
  PLenclave->user_param.migrate_arg = 0;
  memcpy(PLenclave->user_param.name, u_param->name, NAME_LEN);
  if(PLenclave->user_param.elf_ptr == 0 || PLenclave->user_param.elf_size <= 0)
  {
    fprintf(stderr, "LIB: PLencalve_create: ioctl create enclave: elf_ptr is NULL\n");
    return -1;
  }
  ret = ioctl(PLenclave->fd, PENGLAI_ENCLAVE_IOC_CREATE_ENCLAVE, &(PLenclave->user_param));
  if(ret < 0)
  {
    fprintf(stderr, "LIB: PLenclave_create: ioctl create enclave is failed\n");
    return -1;
  }

  PLenclave->eid = PLenclave->user_param.eid;
  return 0;
}

int PLenclave_run(struct PLenclave *PLenclave)
{
  int ret = 0;

  if(PLenclave->fd < 0 || PLenclave->eid < 0)
  {
    fprintf(stderr, "LIB: PLenclave_run: enclave can not be run\n");
    return -1;
  }

  ret = ioctl(PLenclave->fd, PENGLAI_ENCLAVE_IOC_RUN_ENCLAVE, &(PLenclave->user_param));
  if(ret < 0)
  {
    fprintf(stderr, "LIB: PLenclave_run: ioctl run enclave is failed \n");
    return -1;
  }

  return ret; 
}

int PLenclave_attest(struct PLenclave *PLenclave, uintptr_t nonce)
{
  int ret = 0;
  PLenclave->attest_param.isShadow = PLenclave->user_param.isShadow;
  PLenclave->attest_param.eid = PLenclave->eid;
  PLenclave->attest_param.nonce = nonce;
  ret = ioctl(PLenclave->fd, PENGLAI_ENCLAVE_IOC_ATTEST_ENCLAVE, &(PLenclave->attest_param));
  if (PLenclave->user_param.isShadow) {
    printf("\nAttesting: is shadow\n");
  } else {
    printf("\nAttesting: is normal\n");
  }
  if(ret < 0)
  {
    fprintf(stderr, "LIB: ioctl attest enclave is failed ret %d \n", ret);
    return -1;
  }

  return 0; 
}

int PLenclave_stop(struct PLenclave *PLenclave)
{
  int ret =0;
  ret = ioctl(PLenclave->fd, PENGLAI_ENCLAVE_IOC_STOP_ENCLAVE, &(PLenclave->user_param));
  if (ret < 0 )
  {
    fprintf(stderr, "LIB: ioctl stop enclave is failed \n");
    return -1;
  }
  return 0;  
}

int PLenclave_resume(struct PLenclave *PLenclave)
{
  int ret = 0;
  ret = ioctl(PLenclave->fd, PENGLAI_ENCLAVE_IOC_RESUME_ENCLAVE, &(PLenclave->user_param));
  if (ret < 0 )
  {
    fprintf(stderr, "LIB: ioctl stop enclave is failed \n");
    return -1;
  }
  return 0; 
}

int PLenclave_destroy(struct PLenclave *PLenclave)
{
  int ret = 0;
  ret = ioctl(PLenclave->fd, PENGLAI_ENCLAVE_IOC_DESTROY_ENCLAVE, &(PLenclave->user_param));
  if (ret < 0 )
  {
    fprintf(stderr, "LIB: ioctl stop enclave is failed \n");
    return -1;
  }
  return 0;
}

int PLenclave_destruct(struct PLenclave *PLenclave)
{
  int ret = 0;
  ret = close(PLenclave->fd);
  return ret;
}

int PLenclave_fs_persistency_init(int shm_id){
  int ret = 0;
  int fd = open(PENGLAI_ENCLAVE_DEV_PATH, O_RDWR);
  if(fd < 0){
    printf("PLenclave_fs_persistency_init: failed to open enclave dev\n");
    return -1;
  }
  ret = ioctl(fd, PENGLAI_PERSISTENCY_INIT,&shm_id);
  if(ret < 0){
    printf("PLenclave_fs_persistency_init failed\n");
    ret = -1;
  }
  close(fd);
  return ret;
}
