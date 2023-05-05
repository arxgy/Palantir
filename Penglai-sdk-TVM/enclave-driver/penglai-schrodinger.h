#ifndef _PENGLAI_SCHRODINGER_H
#define _PENGLAI_SCHRODINGER_H
#include <linux/types.h>

#define DEFAULT_SCHRODINGER_ORDER        12
#define MIN_PENGLAI_SCHRODINGER_ID       0x10000
#define MAX_PENGLAI_SCHRODINGER_ID       0xfffff

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

struct penglai_schrodinger
{
  int id;
  unsigned long vaddr;
  unsigned long size;
  int refcount;
};

struct penglai_schrodinger* penglai_schrodinger_find(int id);
int penglai_schrodinger_alloc(struct penglai_schrodinger* p);
struct penglai_schrodinger* penglai_schrodinger_free(int id);

int penglai_schrodinger_get(struct file* filep, unsigned long args);
int penglai_schrodinger_at(struct file* filep, unsigned long args);
int penglai_schrodinger_dt(struct file* filep, unsigned long args);
int penglai_schrodinger_ctl(struct file* filep, unsigned long args);

int schrodinger_init(unsigned long vaddr, unsigned long size);
unsigned long schrodinger_alloc(unsigned long size);
int schrodinger_free(unsigned long vaddr, unsigned long size);

#endif /* _PENGLAI_SCHRODINGER_H */
