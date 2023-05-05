#include "types.h"
#include "defs.h"
#include "spinlock.h"
#include "param.h"
#include "buf.h"
#include "stdio.h"
#include "print.h"
#include "string.h"
#include "eapp.h"
#include "print.h"

//FIXME: can remove index field of buf struct? 
#define PREMAPED_SIZE (4096*2)
static uint64 __ramdisk_handle = -1UL;
static void* __premapped_buf = 0;
uint64 get_ramdisk_handle(){
  if(__ramdisk_handle == -1UL){
    __ramdisk_handle = acquire_enclave("ramdisk");
    if(__ramdisk_handle == -1UL){
      eapp_print("acquire ramdisk handle failed\n");
    }
  }
  return __ramdisk_handle;
}

// FIXME: does not need get_premapped_buf anymore
void *get_premapped_buf(){
  if(!__premapped_buf){
    __premapped_buf = eapp_mmap(0,PREMAPED_SIZE);
  }
  return __premapped_buf;
}

struct {
  struct spinlock lock;
  struct buf *buf[NBUF];
  // Linked list of all buffers, through prev/next.
  // head.next is most recently used.
  struct buf head;
} bcache;

void binit(void){
  struct buf *b;
  initlock(&bcache.lock, "bcache");
  // pthread_mutex_init(&bcache.lock,NULL);
  // Create linked list of buffers
  bcache.head.prev = &bcache.head;
  bcache.head.next = &bcache.head;
  for(uint i = 0; i < NBUF; i++){
    bcache.buf[i] = eapp_mmap(0,PREMAPED_SIZE);
    b = bcache.buf[i];
    b->next = bcache.head.next;
    b->prev = &bcache.head;
    b->dev = -1;
    bcache.head.next->prev = b;
    bcache.head.next = b;
  }
  // print_buf_list();
}

// Look through buffer cache for block on device dev.
// If not found, allocate a buffer.
// In either case, return locked buffer.

static struct buf* bget(uint dev, uint blockno)
{
  // print_buf_list();
  struct buf *b;
  int i = 0;
  acquire(&bcache.lock);
  // Is the block already cached?
loop:
  for(b = bcache.head.next; b != &bcache.head; b = b->next){
    if(b->dev == dev && b->blockno == blockno){
      if(!(b->flags & B_BUSY)){
        b->flags |= B_BUSY;
        // remove b from the LRU list
        b->next->prev = b->prev;
        b->prev->next = b->next;
        release(&bcache.lock);
        return b;
      }
      sleep(b,&bcache.lock);
      goto loop;
    }
  }
  // Not cached; recycle an unused buffer.
  b = bcache.head.prev;
  while(b != (&bcache.head)){
    if((b->flags & B_BUSY) == 0 && (b->flags & B_DIRTY) == 0) {
      b->dev = dev;
      b->blockno = blockno;
      b->flags = B_BUSY;
      b->next->prev = b->prev;
      b->prev->next = b->next;
      release(&bcache.lock);
      return b;
    }
    b = b->prev;
  }
  panic("bget: no buffers");
}

// FIXME: b is mmap memory
static void ramdiskrw(struct buf* b){
  struct call_enclave_arg_t call_arg;
  call_arg.req_vaddr = b;
  call_arg.req_size = PREMAPED_SIZE;
  int status = call_enclave(get_ramdisk_handle(),&call_arg);
  b = call_arg.req_vaddr;
  if(status || call_arg.resp_val){
    eapp_print("ramdiskrw failed\n");
  }
}
// Return a locked buf with the contents of the indicated block.

struct buf* bread(uint dev, uint blockno)
{
  // eapp_print("bread block_no: %d\n",blockno);
  struct buf *b;
  b = bget(dev, blockno);
  if(!(b->flags & B_VALID)) {
    ramdiskrw(b);
    b->flags |= B_VALID;
  }
  return b;
}



// Write b's contents to disk.  Must be locked.
// FIXME: how to check if the current thread holding a lock
// DONE: pthread_mutex_t cannot acomplish this

void bwrite(struct buf *b)
{
  if((b->flags & B_BUSY) == 0){
    panic("bwrite");
  }
  b->flags |= B_DIRTY;
  ramdiskrw(b);
}

// Release a locked buffer.
// Move to the head of the MRU list.

void brelse(struct buf *b)
{
  // eapp_print("brelse begin, b:0x%lx\n",b);
  if((b->flags & B_BUSY) == 0){
    panic("brelse");
  }
  acquire(&bcache.lock);
  // b->next->prev = b->prev;
  // b->prev->next = b->next;
  b->next = bcache.head.next;
  b->prev = &bcache.head;
  bcache.head.next->prev = b;
  bcache.head.next = b;
  b->flags &= ~B_BUSY;
  release(&bcache.lock);
  // print_buf_list();
}

void panic(const char* s){
  eapp_print("panic: %s\n",s);
  EAPP_RETURN(-1);
}

void print_buf_list(){
  struct buf* tmp_b;
  int i = 0;
  for(tmp_b = bcache.head.next; tmp_b != &bcache.head; tmp_b = tmp_b->next){
      eapp_print("i: %d, b: 0x%lx\n",i++,tmp_b);
   }
}