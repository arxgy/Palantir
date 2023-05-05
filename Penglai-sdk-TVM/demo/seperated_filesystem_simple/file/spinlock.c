#include "types.h"
#include "param.h"
#include "defs.h"
#include "spinlock.h"

void initlock(struct spinlock *lk, char *name)
{
  lk->name = name;
  lk->locked = 0;
  lk->cpu = 0;
}

void acquire(struct spinlock *lk)
{
}


void release(struct spinlock *lk)
{
}


void wakeup(void* addr) {
}


void sleep(void* addr, struct spinlock* lk) {
}