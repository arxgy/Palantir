#include "types.h"
#include "param.h"
#include "defs.h"
#include "spinlock.h"
#include "stdio.h"
#include "string.h"
#include"buf.h"
#include "print.h"
#include "fs.h"
// Simple logging that allows concurrent FS system calls.
//
// A log transaction contains the updates of multiple FS system
// calls. The logging system only commits when there are
// no FS system calls active. Thus there is never
// any reasoning required about whether a commit might
// write an uncommitted system call's updates to disk.
//
// A system call should call begin_op()/end_op() to mark
// its start and end. Usually begin_op() just increments
// the count of in-progress FS system calls and returns.
// But if it thinks the log is close to running out, it
// sleeps until the last outstanding end_op() commits.
//
// The log is a physical re-do log containing disk blocks.
// The on-disk log format:
//   header block, containing block #s for block A, B, C, ...
//   block A
//   block B
//   block C
//   ...
// Log appends are synchronous.

// Contents of the header block, used for both the on-disk header block
// and to keep track in memory of logged block# before commit.
struct logheader {
  int n;
  int block[LOGSIZE];
};

struct log {
  // pthread_mutex_t lock;
  // pthread_cond_t condition;
  struct spinlock lock;
  int start;
  int size;
  int outstanding; // how many FS sys calls are executing.
  int committing;  // in commit(), please wait.
  int dev;
  struct logheader lh;
};

struct log log;

static void recover_from_log(void);
static void commit();


void _initlog(int dev, uint logstart, uint nlog)
{
  if (sizeof(struct logheader) >= BSIZE){
    panic("initlog: too big logheader"); 
    // fprintf(stderr, "initlog: too big logheader");
  }

  initlock(&log.lock, "log");
  // pthread_mutex_init(&log.lock, NULL);
  // pthread_cond_init(&log.condition, NULL);
  log.start = logstart;
  log.size = nlog;
  log.dev = dev;
  recover_from_log();
}
void initlog(uint dev,struct superblock* sb){
    _initlog(dev, sb->logstart, sb->nlog);
}

// Copy committed blocks from log to their home location

static void install_trans(void)
{
  int tail;

  for (tail = 0; tail < log.lh.n; tail++) {
    //struct buf *lbuf = bread(log.dev, log.start+tail+1); // read log block
    struct buf *dbuf = bread(log.dev, log.lh.block[tail]); // read dst
    //memmove(dbuf->data, lbuf->data, BSIZE);  // copy block to dst
    bwrite(dbuf);  // write dst to disk
    // bunpin(dbuf);
    //brelse(lbuf);
    brelse(dbuf);
  }
}

// Read the log header from disk into the in-memory log header

static void read_head(void)
{
  struct buf *buf = bread(log.dev, log.start);
  struct logheader *lh = (struct logheader *) (buf->data);
  int i; 
  log.lh.n = lh->n;
  for (i = 0; i < log.lh.n; i++) {
    log.lh.block[i] = lh->block[i];
  }
  brelse(buf);
}

// Write in-memory log header to disk.
// This is the true point at which the
// current transaction commits.

static void write_head(void)
{
  struct buf *buf = bread(log.dev, log.start);
  struct logheader *hb = (struct logheader *) (buf->data);
  int i;
  hb->n = log.lh.n;
  for (i = 0; i < log.lh.n; i++) {
    hb->block[i] = log.lh.block[i];
  }
  bwrite(buf);
  // ramdiskflush();
  brelse(buf);
}


static void recover_from_log(void)
{
  read_head();
  install_trans(); // if committed, copy from log to disk
  log.lh.n = 0;
  write_head(); // clear the log
}


// called at the start of each FS system call.

void begin_op(void)
{
  acquire(&log.lock);
  // pthread_mutex_lock(&log.lock);
  while(1){
    if(log.committing){
      sleep(&log, &log.lock);
      // pthread_cond_wait(&log.condition, &log.lock);
    } else if(log.lh.n + (log.outstanding+1)*MAXOPBLOCKS > LOGSIZE){
      // this op might exhaust log space; wait for commit.
      sleep(&log, &log.lock);
      // pthread_cond_wait(&log.condition, &log.lock);
    } else {
      log.outstanding += 1;
      release(&log.lock);
      // pthread_mutex_unlock(&log.lock);
      break;
    }
  }
}


// called at the end of each FS system call.
// commits if this was the last outstanding operation.
void end_op(void)
{
  int do_commit = 0;

  acquire(&log.lock);
  // pthread_mutex_lock(&log.lock);
  log.outstanding -= 1;
  if(log.committing)
    panic("log.committing");
  if(log.outstanding == 0){
    do_commit = 1;
    log.committing = 1;
  } else {
    // begin_op() may be waiting for log space,
    // and decrementing log.outstanding has decreased
    // the amount of reserved space.
    wakeup(&log);
    // pthread_cond_signal(&log.condition);
  }
  release(&log.lock);
  // pthread_mutex_unlock(&log.lock);

  if(do_commit){
    // call commit w/o holding locks, since not allowed
    // to sleep with locks.
    commit();
    acquire(&log.lock);
    // pthread_mutex_lock(&log.lock);
    log.committing = 0;
    wakeup(&log);
    // pthread_cond_signal(&log.condition);
    release(&log.lock);
    // pthread_mutex_unlock(&log.lock);
  }
}


// Copy modified blocks from cache to log.

static void write_log(void)
{
  int tail;

  for (tail = 0; tail < log.lh.n; tail++) {
    struct buf *to = bread(log.dev, log.start+tail+1); // log block
    struct buf *from = bread(log.dev, log.lh.block[tail]); // cache block
    memmove(to->data, from->data, BSIZE);
    bwrite(to);  // write the log
    brelse(from);
    brelse(to);
  }
}


static void commit()
{
  //if (log.lh.n > 0) {
  if (log.lh.n > MINCOMMITSIZE) {
    write_log();     // Write modified blocks from cache to log
    write_head();    // Write header to disk -- the real commit
    install_trans(); // Now install writes to home locations
    log.lh.n = 0;
    write_head();    // Erase the transaction from the log
  }
}


// Caller has modified b->data and is done with the buffer.
// Record the block number and pin in the cache by increasing refcnt.
// commit()/write_log() will do the disk write.
//
// log_write() replaces bwrite(); a typical use is:
//   bp = bread(...)
//   modify bp->data[]
//   log_write(bp)
//   brelse(bp)

void log_write(struct buf *b)
{
  int i;
  if (log.lh.n >= LOGSIZE || log.lh.n >= log.size - 1)
    panic("too big a transaction");
  if (log.outstanding < 1)
    panic("log_write outside of trans");

  acquire(&log.lock);
  // pthread_mutex_lock(&log.lock);
  for (i = 0; i < log.lh.n; i++) {
    if (log.lh.block[i] == b->blockno)   // log absorbtion
      break;
  }
  log.lh.block[i] = b->blockno;
  if (i == log.lh.n) {  // Add new block to log?
    // bpin(b);
    log.lh.n++;
  }
  b->flags |= B_DIRTY;
  release(&log.lock);

  // pthread_mutex_unlock(&log.lock);
}
