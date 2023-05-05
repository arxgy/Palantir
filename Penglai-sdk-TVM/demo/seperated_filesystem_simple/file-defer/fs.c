#include "types.h"
#include "defs.h"
#include "fs.h"
#include "param.h"
#include "buf.h"
#include "stdio.h"
#include "spinlock.h"
#include "file.h"
#include "stat.h"
// #include "proc.h"
#include "string.h"
#include "print.h"
#define min(a, b) ((a) < (b) ? (a) : (b))
// there should be one superblock per disk device, but we run with
// only one device
struct superblock sb; 

// Read the super block.

static void readsb(int dev, struct superblock *sb)
{
  struct buf *bp;

  bp = bread(dev, 1);
  memmove(sb, bp->data, sizeof(struct superblock));
  brelse(bp);
}

// Init fs

void fsinit(int dev) {
  readsb(dev, &sb);
  if(sb.magic != FSMAGIC)
    panic("invalid file system");
  initlog(dev,&sb);
}

// Zero a block.

// FIXME: may need to modify to another name to avoid messing  to the libc? 
static void xv6_bzero(int dev, int bno)
{
  struct buf *bp;

#if 0
  bp = bread(dev, bno);
  memset(bp->data, 0, BSIZE);
#else
  bp = bread_zero(dev, bno);
#endif
  log_write(bp);
  brelse(bp);
}

// Allocate a zeroed disk block.

static uint balloc(uint dev)
{
  int b, bi, m;
  struct buf *bp;
  bp = 0;
  for(b = 0; b < sb.size; b += BPB){
    bp = bread(dev, BBLOCK(b, sb));
    for(bi = 0; bi < BPB && b + bi < sb.size; bi++){
      m = 1 << (bi % 8);
      if((bp->data[bi/8] & m) == 0){  // Is block free?
        bp->data[bi/8] |= m;  // Mark block in use.
        log_write(bp);
        brelse(bp);
        xv6_bzero(dev, b + bi);
        return b + bi;
      }
    }
    brelse(bp);
  }
  panic("balloc: out of blocks");
  /*Never reach here, fix compile warning*/
  return -1;
}

// Free a disk block.

static void bfree(int dev, uint b)
{
  struct buf *bp;
  int bi, m;

  bp = bread(dev, BBLOCK(b, sb));
  bi = b % BPB;
  m = 1 << (bi % 8);
  if((bp->data[bi/8] & m) == 0)
    panic("freeing free block");
  bp->data[bi/8] &= ~m;
  log_write(bp);
  brelse(bp);
}
struct {
  struct spinlock lock;
  struct inode inode[NINODE];
} icache;


void iinit()
{
  int i = 0;
  
  initlock(&icache.lock, "icache");
}

static struct inode* iget(uint dev, uint inum);

// Allocate an inode on device dev.
// Mark it as allocated by  giving it type type.
// Returns an unlocked but allocated and referenced inode.

struct inode* ialloc(uint dev, short type)
{
  int inum;
  struct buf *bp;
  struct dinode *dip;

  for(inum = 1; inum < sb.ninodes; inum++){
    bp = bread(dev, IBLOCK(inum, sb));
    dip = (struct dinode*)bp->data + inum%IPB;
    if(dip->type == 0){  // a free inode
      memset(dip, 0, sizeof(*dip)); // so the flags are cleared
      dip->type = type;
      log_write(bp);   // mark it allocated on the disk
      brelse(bp);
      return iget(dev, inum);
    }
    brelse(bp);
  }
  panic("ialloc: no inodes");
  /*Never reach here, fix compile warning*/
  return NULL;
}

// Copy a modified in-memory inode to disk.
// Must be called after every change to an ip->xxx field
// that lives on disk, since i-node cache is write-through.
// Caller must hold ip->lock.

void iupdate(struct inode *ip)
{
  struct buf *bp;
  struct dinode *dip;

  bp = bread(ip->dev, IBLOCK(ip->inum, sb));
  dip = (struct dinode*)bp->data + ip->inum%IPB;
  dip->type = ip->type;
  dip->major = ip->major;
  dip->minor = ip->minor;
  dip->nlink = ip->nlink;
  dip->size = ip->size;
  memmove(dip->addrs, ip->addrs, sizeof(ip->addrs));
  log_write(bp);
  brelse(bp);
}

// Find the inode with number inum on device dev
// and return the in-memory copy. Does not lock
// the inode and does not read it from disk.

static struct inode* iget(uint dev, uint inum)
{
  struct inode *ip, *empty;

  acquire(&icache.lock);
  // pthread_mutex_lock(&icache.lock);
  // Is the inode already cached?
  empty = 0;
  for(ip = &icache.inode[0]; ip < &icache.inode[NINODE]; ip++){
    if(ip->ref > 0 && ip->dev == dev && ip->inum == inum){
      ip->ref++;
      release(&icache.lock);
      // pthread_mutex_unlock(&icache.lock);
      return ip;
    }
    if(empty == 0 && ip->ref == 0)    // Remember empty slot.
      empty = ip;
  }

  // Recycle an inode cache entry.
  if(empty == 0)
    panic("iget: no inodes");

  ip = empty;
  ip->dev = dev;
  ip->inum = inum;
  ip->ref = 1;
  ip->flags = 0;
  release(&icache.lock);
  // pthread_mutex_unlock(&icache.lock);
  return ip;
}

// Increment reference count for ip.
// Returns ip to enable ip = idup(ip1) idiom.

struct inode* idup(struct inode *ip)
{
  acquire(&icache.lock);
  // pthread_mutex_lock(&icache.lock);
  ip->ref++;
  release(&icache.lock);
  // pthread_mutex_unlock(&icache.lock);
  return ip;
}

// Lock the given inode.
// Reads the inode from disk if necessary.

void ilock(struct inode *ip)
{
  struct buf *bp;
  struct dinode *dip;

  if(ip == 0 || ip->ref < 1)
    panic("ilock");

//   acquiresleep(&ip->lock);
  // pthread_mutex_lock(&ip->lock);
  acquire(&icache.lock);
  while (ip->flags & I_BUSY)
  {
    sleep(ip,&icache.lock);
  }
  ip->flags |= I_BUSY;
  if(!(ip->flags & I_VALID)){
    bp = bread(ip->dev, IBLOCK(ip->inum, sb));
    dip = (struct dinode*)bp->data + ip->inum%IPB;
    ip->type = dip->type;
    ip->major = dip->major;
    ip->minor = dip->minor;
    ip->nlink = dip->nlink;
    ip->size = dip->size;
    memmove(ip->addrs, dip->addrs, sizeof(ip->addrs));
    brelse(bp);
    // ip->valid = 1;
    ip->flags |= I_VALID; 
    if(ip->type == 0)
      panic("ilock: no type");
  }
}

// Unlock the given inode.

void iunlock(struct inode *ip)
{
    //FIXME: just remove the lock holding check currently
   if(ip == 0 || ip->ref < 1 || !(ip->flags & I_BUSY))
      panic("iunlock");
   acquire(&icache.lock);
   ip->flags &= ~I_BUSY;
   wakeup(ip);   
   release(&icache.lock);
//   releasesleep(&ip->lock);
  // pthread_mutex_unlock(&ip->lock);
}

// Drop a reference to an in-memory inode.
// If that was the last reference, the inode cache entry can
// be recycled.
// If that was the last reference and the inode has no links
// to it, free the inode (and its content) on disk.
// All calls to iput() must be inside a transaction in
// case it has to free the inode.

void iput(struct inode *ip)
{
  acquire(&icache.lock);
  // pthread_mutex_lock(&icache.lock);
  if(ip->ref == 1 && (ip->flags & I_VALID) && ip->nlink == 0){
    // inode has no links and no other references: truncate and free.

    // ip->ref == 1 means no other process can have ip locked,
    // so this acquiresleep() won't block (or deadlock).
    // acquiresleep(&ip->lock);
    if(ip->flags & I_BUSY){
      panic("iput busy");
    }
    // pthread_mutex_lock(&ip->lock);
    // release(&icache.lock);
    ip->flags |= I_BUSY;
    release(&icache.lock);
    // pthread_mutex_unlock(&icache.lock);
    itrunc(ip);
    ip->type = 0;
    iupdate(ip);
    acquire(&icache.lock);
    ip->flags = 0;
    wakeup(ip);
    // releasesleep(&ip->lock);
    // pthread_mutex_unlock(&ip->lock);
    // acquire(&icache.lock);
    // pthread_mutex_lock(&icache.lock);
  }

  ip->ref--;
  release(&icache.lock);
  // pthread_mutex_unlock(&icache.lock);
}

// Common idiom: unlock, then put.
void
iunlockput(struct inode *ip)
{
  iunlock(ip);
  iput(ip);
}

// Inode content
//
// The content (data) associated with each inode is stored
// in blocks on the disk. The first NDIRECT block numbers
// are listed in ip->addrs[].  The next NINDIRECT blocks are
// listed in block ip->addrs[NDIRECT].

// Return the disk block address of the nth block in inode ip.
// If there is no such block, bmap allocates one.
static uint bmap(struct inode *ip, uint bn)
{
  uint addr, *a;
  struct buf *bp;
  struct buf tmp_buf;
  if(bn < NDIRECT){
    if((addr = ip->addrs[bn]) == 0)
      ip->addrs[bn] = addr = balloc(ip->dev);
    return addr;
  }
  bn -= NDIRECT;

  if(bn < NINDIRECT){
    // Load indirect block, allocating if necessary.
    if((addr = ip->addrs[NDIRECT]) == 0)
      ip->addrs[NDIRECT] = addr = balloc(ip->dev);
    bp = bread(ip->dev, addr);
    a = (uint*)bp->data;
    if((addr = a[bn]) == 0){
      a[bn] = addr = balloc(ip->dev);
      log_write(bp);
    }
    brelse(bp);
    return addr;
  }

    if (bn < MAXFILE-NDIRECT) {
    int bni;
    bn -= NINDIRECT;
    if((addr = ip->addrs[NDIRECT+1]) == 0) {
      ip->addrs[NDIRECT+1] = addr = balloc(ip->dev);   // allocate double indirect block
    }    
    bp = bread(ip->dev, addr);  
    a = (uint*)bp->data;
    bni = bn / NINDIRECT;
    if((addr = a[bni]) == 0){
      a[bni] = addr = balloc(ip->dev);   // allocate indirect block
      log_write(bp);
    }
    brelse(bp);
    bp = bread(ip->dev, addr);
    a = (uint*)bp->data;
    bni = bn % NINDIRECT;
    if((addr = a[bni]) == 0){
      memcpy(&tmp_buf,bp,sizeof(struct buf));
      a[bni] = addr = balloc(ip->dev);   // allocate block
      memcpy(bp,&tmp_buf,sizeof(struct buf));
      log_write(bp);
    }
    brelse(bp);
    bp = bread(ip->dev, addr);
    brelse(bp);
    return addr;
  }
// FIXME: does not support double-indirected yet
  panic("bmap: out of range");
  /*Never reach here, fix compile warning*/
  return -1;
}


// Truncate inode (discard contents).
// Only called when the inode has no links
// to it (no directory entries referring to it)
// and has no in-memory reference to it (is
// not an open file or current directory).
void itrunc(struct inode *ip)
{
  int i, j;
  struct buf *bp;
  uint *a;
  struct buf tmp_buf,tmp_buf2;
  for(i = 0; i < NDIRECT; i++){
    if(ip->addrs[i]){
      bfree(ip->dev, ip->addrs[i]);
      ip->addrs[i] = 0;
    }
  }

  if(ip->addrs[NDIRECT]){
    bp = bread(ip->dev, ip->addrs[NDIRECT]);
    a = (uint*)bp->data;
    for(j = 0; j < NINDIRECT; j++){
      if(a[j])
      {
        bfree(ip->dev, a[j]);
      }
    }
    brelse(bp);
    bfree(ip->dev, ip->addrs[NDIRECT]);
    ip->addrs[NDIRECT] = 0;
  }
  if(ip->addrs[NDIRECT+1]){
    bp = bread(ip->dev,ip->addrs[NDIRECT + 1]);
      a = (uint*)bp->data;
      uint* b;
      struct buf *next_level_bp;
      int k;
      for(j = 0; j < NINDIRECT;j++){
        if(a[j]){
          next_level_bp = bread(ip->dev,a[j]);
          b = (uint*)next_level_bp->data;
          for(k = 0; k < NINDIRECT; k++){
            if(b[k]){
              bfree(ip->dev,b[k]);
            }
            else{
              break; // FIXME: can just break?
            }
          }
          brelse(next_level_bp);
          bfree(ip->dev,a[j]);
        }
        else{
          break; //FIXME: can just break?
        }
      }
      brelse(bp);
      bfree(ip->dev,ip->addrs[NDIRECT+1]);
      ip->addrs[NDIRECT+1] = 0;
    }
  ip->size = 0;
  iupdate(ip);
}


// Copy stat information from inode.
// Caller must hold ip->lock.
void stati(struct inode *ip, struct stat *st)
{
  st->dev = ip->dev;
  st->ino = ip->inum;
  st->type = ip->type;
  st->nlink = ip->nlink;
  st->size = ip->size;
}

// Read data from inode.
// Caller must hold ip->lock.
// If user_dst==1, then dst is a user virtual address;
// otherwise, dst is a kernel address.
int readi(struct inode *ip, uint64 dst, uint off, uint n)
{
  uint tot, m;
  struct buf *bp;
  if(off > ip->size || off + n < off)
    return -1;
  if(off + n > ip->size)
    n = ip->size - off;

  for(tot=0; tot<n; tot+=m, off+=m, dst+=m){
    bp = bread(ip->dev, bmap(ip, off/BSIZE));
    m = min(n - tot, BSIZE - off%BSIZE);
    // FIXME: should modify this memory copy  and can modify the interface also
    // if(either_copyout(user_dst, dst, bp->data + (off % BSIZE), m) == -1) {
    //   brelse(bp);
    //   break;
    // }
    // memcpy((char*)dst, bp->data + (off % BSIZE), m);
    memmove((char*)dst,bp->data + (off % BSIZE), m);
    brelse(bp);
  }
  return n;
}

// Write data to inode.
// Caller must hold ip->lock.
// If user_src==1, then src is a user virtual address;
// otherwise, src is a kernel address.
int writei(struct inode *ip, uint64 src, uint off, uint n)
{
  uint tot, m;
  struct buf *bp;
  // eapp_print("off: %d, ip->size: %d, n: %d",off,ip->size,n);
  if(off > ip->size || off + n < off)
    return -1;
  if(off + n > MAXFILE*BSIZE)
    return -1;

  for(tot=0; tot<n; tot+=m, off+=m, src+=m){
    bp = bread(ip->dev, bmap(ip, off/BSIZE));
    m = min(n - tot, BSIZE - off%BSIZE);
    memmove(bp->data + (off % BSIZE), (char*)src, m);
    log_write(bp);
    brelse(bp);
  }

  if(n > 0){
    if(off > ip->size)
      ip->size = off;
    // write the i-node back to disk even if the size didn't change
    // because the loop above might have called bmap() and added a new
    // block to ip->addrs[].
    iupdate(ip);
  }

  return n;
}

// Directories
int namecmp(const char *s, const char *t)
{
  return strncmp(s, t, DIRSIZ);
}

// Look for a directory entry in a directory.
// If found, set *poff to byte offset of entry.
struct inode* dirlookup(struct inode *dp, char *name, uint *poff)
{
  uint off, inum;
  struct dirent de;

  if(dp->type != T_DIR)
    panic("dirlookup not DIR");

  for(off = 0; off < dp->size; off += sizeof(de)){
    if(readi(dp,(uint64)&de, off, sizeof(de)) != sizeof(de))
      panic("dirlookup read");
    if(de.inum == 0)
      continue;
    if(namecmp(name, de.name) == 0){
      // entry matches path element
      if(poff)
        *poff = off;
      inum = de.inum;
      return iget(dp->dev, inum);
    }
  }

  return 0;
}

// Write a new directory entry (name, inum) into the directory dp.
int dirlink(struct inode *dp, char *name, uint inum)
{
  int off;
  struct dirent de;
  struct inode *ip;

  // Check that name is not present.
  if((ip = dirlookup(dp, name, 0)) != 0){
    iput(ip);
    return -1;
  }

  // Look for an empty dirent.
  for(off = 0; off < dp->size; off += sizeof(de)){
    if(readi(dp, (uint64)&de, off, sizeof(de)) != sizeof(de))
      panic("dirlink read");
    if(de.inum == 0)
      break;
  }

  strncpy(de.name, name, DIRSIZ);
  de.inum = inum;
  if(writei(dp, (uint64)&de, off, sizeof(de)) != sizeof(de))
    panic("dirlink");

  return 0;
}

// Paths

// Copy the next path element from path into name.
// Return a pointer to the element following the copied one.
// The returned path has no leading slashes,
// so the caller can check *path=='\0' to see if the name is the last one.
// If no name to remove, return 0.
//
// Examples:
//   skipelem("a/bb/c", name) = "bb/c", setting name = "a"
//   skipelem("///a//bb", name) = "bb", setting name = "a"
//   skipelem("a", name) = "", setting name = "a"
//   skipelem("", name) = skipelem("////", name) = 0
//
static char* skipelem(char *path, char *name)
{
  char *s;
  int len;

  while(*path == '/')
    path++;
  if(*path == 0)
    return 0;
  s = path;
  while(*path != '/' && *path != 0)
    path++;
  len = path - s;
  if(len >= DIRSIZ)
    memmove(name, s, DIRSIZ);
  else {
    memmove(name, s, len);
    name[len] = 0;
  }
  while(*path == '/')
    path++;
  return path;
}


// Look up and return the inode for a path name.
// If parent != 0, return the inode for the parent and copy the final
// path element into name, which must have room for DIRSIZ bytes.
// Must be called inside a transaction since it calls iput().
static struct inode* namex(char *path, int nameiparent, char *name)
{
  struct inode *ip, *next;

  if(*path == '/')
    ip = iget(ROOTDEV, ROOTINO);
  else
  {
    panic("only support absolute path at this moment\n");
  }
    // ip = idup(curproc->cwd);

  while((path = skipelem(path, name)) != 0){
    ilock(ip);
    if(ip->type != T_DIR){
      iunlockput(ip);
      return 0;
    }
    if(nameiparent && *path == '\0'){
      // Stop one level early.
      iunlock(ip);
      return ip;
    }
    if((next = dirlookup(ip, name, 0)) == 0){
      iunlockput(ip);
      return 0;
    }
    iunlockput(ip);
    ip = next;
  }
  if(nameiparent){
    iput(ip);
    return 0;
  }
  return ip;
}


struct inode* namei(char *path)
{
  char name[DIRSIZ];
  return namex(path, 0, name);
}


struct inode* nameiparent(char *path, char *name)
{
  return namex(path, 1, name);
}

