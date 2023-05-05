#ifndef __RAMDISK__
#define __RAMDISK__
#include "types.h"
#define ROOTINO 1
#define BSIZE 4096
#define FSMAGIC 0x10203040
#define NDIRECT 11
#define T_DIR     1   // Directory
#define T_FILE    2   // File
#define T_DEVICE  3   // Device
// Inodes per block.
#define IPB           (BSIZE / sizeof(struct dinode))

// Block containing inode i

#define FSSIZE 1000
#define NINODES 200
#define NINDIRECT (BSIZE / sizeof(uint))
#define NDINDIRECT (NINDIRECT*NINDIRECT)
#define MAXFILE (NDIRECT + NINDIRECT + NDINDIRECT)
#define MAXOPBLOCKS  10  // max # of blocks any FS op writes
#define LOGSIZE      (MAXOPBLOCKS*3)  // max data blocks in on-disk log
#define INODESTART 2 + LOGSIZE
#define IBLOCK(i)  ((i/IPB) + INODESTART)
#define BPB (BSIZE*8)
#define BMAPSTART (2 + LOGSIZE + NINODES / IPB + 1)

struct superblock
{
 uint magic;
 uint size;
 uint nblocks;      // Number of data blocks
 uint ninodes;      // Number of inodes.
 uint nlog;         // Number of log blocks
 uint logstart;     // Block number of first log block
 uint inodestart;   // Block number of first inode block
 uint bmapstart;    // Block number of first free map block   
};

#define DIRSIZ 62

struct dirent {
  ushort inum;
  char name[DIRSIZ];
};



struct dinode {
  short type;           // File type
  short major;          // Major device number (T_DEVICE only)
  short minor;          // Minor device number (T_DEVICE only)
  short nlink;          // Number of links to inode in file system
  uint size;            // Size of file (bytes)
  uint addrs[NDIRECT+2];   // Data block addresses
};
#define B_BUSY 0x1
#define B_VALID 0x2
#define B_DIRTY 0x4
#endif