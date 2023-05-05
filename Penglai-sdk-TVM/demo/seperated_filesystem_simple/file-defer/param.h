#ifndef __FILE_PARAM__
#define __FILE_PARAM__
#define NOFILE       16  // open files per process
#define NFILE       100  // open files per system
#define NINODE       50  // maximum number of active i-nodes
#define NDEV         10  // maximum major device number
#define ROOTDEV       1  // device number of file system root disk
#define MAXOPBLOCKS  10  // max # of blocks any FS op writes
#define MAXPATH      128   // maximum file path name
#define BLOCKSIZE 4096 // block size
#define BSIZE 4096  // block size
#define LOGSIZE      (MAXOPBLOCKS*10)  // max data blocks in on-disk log
#define NBUF         (MAXOPBLOCKS*10)  // size of disk block cache
#define MINCOMMITSIZE (MAXOPBLOCKS*6)  // Only commit when we have such many logs
#endif
