#ifndef _PENGLAI_BUDDY_H
#define _PENGLAI_BUDDY_H

struct buddy_mm_t{
  //spinlock_t
  int available;
  unsigned long vaddr;
  unsigned long size;
};

struct buddy_mm_t* penglai_buddy_init(unsigned long vaddr, unsigned long size);
unsigned long penglai_buddy_alloc(struct buddy_mm_t* mm, unsigned long size);
int penglai_buddy_free(struct buddy_mm_t* mm, unsigned long vaddr, unsigned long size);
int penglai_buddy_destroy(struct buddy_mm_t *mm);

#endif /* _PENGLAI_BUDDY_H  */
