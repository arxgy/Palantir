#ifndef __FILE_DEF__
#define __FILE_DEF__
struct spinlock;
struct inode;
struct stat;
struct file;
struct pipe;
struct superblock;
// file.c
struct file*    filealloc(void);
void            fileclose(struct file*);
struct file*    filedup(struct file*);
void            fileinit(void);
int             fileread(struct file*, uint64, int n);
int             filestat(struct file*, uint64 addr);
int             filewrite(struct file*, uint64, int n);

// fs.c
void            fsinit(int);
int             dirlink(struct inode*, char*, uint);
struct inode*   dirlookup(struct inode*, char*, uint*);
struct inode*   ialloc(uint, short);
struct inode*   idup(struct inode*);
void            iinit();
void            ilock(struct inode*);
void            iput(struct inode*);
void            iunlock(struct inode*);
void            iunlockput(struct inode*);
void            iupdate(struct inode*);
int             namecmp(const char*, const char*);
struct inode*   namei(char*);
struct inode*   nameiparent(char*, char*);
int             readi(struct inode*, uint64, uint, uint);
void            stati(struct inode*, struct stat*);
int             writei(struct inode*,uint64, uint, uint);
void             itrunc(struct inode *);
// sys_file.c
int sys_open(char*, int);
int sys_close(int);
int sys_read(int, void*, int);
int sys_read(int, void*,int);
int sys_ftruncate(int );
int sys_unlink(const char* path);


//spinlock
void initlock(struct spinlock *, char *);
void acquire(struct spinlock *);
void release(struct spinlock *);
void wakeup(void* );
void sleep(void* , struct spinlock*);

//pipe.c
int             pipealloc(struct file**, struct file**);
void            pipeclose(struct pipe*, int);
int             piperead(struct pipe*, uint64, int);
int             pipewrite(struct pipe*, uint64, int);

//boi_interface
void binit(void);
void            begin_op();
void            end_op();
struct buf*     bread(uint,uint);
struct buf*     bread_zero(uint,uint);
void            log_write(struct buf*);
void            panic(const char*);
void            brelse(struct buf*);
void            initlog(uint,struct superblock*);
struct buf*     bread2(uint,uint);

//bio.c
void   bwrite(struct buf*);
void print_buf_list();
#endif
