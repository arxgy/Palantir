#ifndef _PENGLAI_SHM
#define _PENGLAI_SHM
#include <linux/types.h>

#define MIN_PENGLAI_SHMID              0x10000
#define MAX_PENGLAI_SHMID              0xfffff

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

struct penglai_shm
{
  int shmid;
  unsigned long vaddr;
  unsigned long size;
  int refcount;
};

struct penglai_shm* penglai_shm_find(int shmid);
int penglai_shm_alloc(struct penglai_shm* shm);
struct penglai_shm* penglai_shm_free(int shmid);

int penglai_shmget(struct file* filep, unsigned long args);
int penglai_shmat(struct file* filep, unsigned long args);
int penglai_shmdt(struct file* filep, unsigned long args);
int penglai_shmctl(struct file* filep, unsigned long args);

#endif /* _PENGLAI_SHM */
