#include "types.h"
#include "defs.h"
#include "fs.h"
#include "fcntl.h"
#include "file.h"
#include "string.h"
#include "param.h"
#include "stat.h"
#include "structure.h"
#include "print.h"
static struct file *open_file[NOFILE];
static int fdalloc(struct file* file){
  int fd;
  for(fd = 3; fd < NOFILE+3; fd ++){
    if(open_file[fd - 3] == 0){
      open_file[fd - 3] = file;
      return fd;
    }
  }
  return -1;
}

static struct inode* create(char* path, short type, short major, short minor){
  uint off;
  struct inode *ip, *dp;
  char name[DIRSIZ];
  if((dp = nameiparent(path, name)) == 0){
    return 0;
  }

  ilock(dp);
  if((ip = dirlookup(dp, name, &off)) != 0){
    iunlockput(dp);
    ilock(ip);
    if(type == T_FILE && ip->type == T_FILE)
      return ip;
    iunlockput(ip);
    return 0;
  }
  if((ip = ialloc(dp->dev, type)) == 0)
    panic("create: ialloc");

  ilock(ip);
  ip->major = major;
  ip->minor = minor;
  ip->nlink = 1;
  iupdate(ip);
  if(type == T_DIR){  // Create . and .. entries.
    dp->nlink++;  // for ".."
    iupdate(dp);
    // No ip->nlink++ for ".": avoid cyclic ref count.
    if(dirlink(ip, ".", ip->inum) < 0 || dirlink(ip, "..", dp->inum) < 0)
      panic("create dots");
  }
  if(dirlink(dp, name, ip->inum) < 0)
    panic("create: dirlink");

  iunlockput(dp);

  return ip;
}
int sys_open(char* path, int omode){
    struct file* file;
    struct inode* ip;
    int fd;
    begin_op();

    if(omode & XV6_O_CREATE){
        ip = create(path, T_FILE, 0, 0);
        if(ip == 0){
          end_op();
          return -1;
        }
    }
    else{
      if((ip = namei(path)) == 0){
        end_op();
        return -1;
      }
      ilock(ip);
      if(ip->type == T_DIR && omode != XV6_O_RDONLY ){
        iunlockput(ip);
        end_op();
        return -1;
      }
    }   
    if((file = filealloc()) == 0 || (fd = fdalloc(file)) == 0){
      if(file){
        fileclose(file);
      }
      iunlockput(ip);
      end_op();
      return -1; 
    }

    file->type = FD_INODE;
    file->ip = ip;
    file->off = 0;
    file->major = 0;
    file->readable = !(omode & XV6_O_WRONLY);
    file->writable = (omode & XV6_O_WRONLY) || (omode & XV6_O_RDWR);
    if(omode & XV6_O_APPEND){
      file->off = ip->size;
    }
    iunlock(ip);
    end_op();
    return fd;
}

int sys_ftruncate(int fd){ //only support truncate to 0 now
  if(fd >= NOFILE + 3){
    return -1;
  }
  struct file *file = open_file[fd-3];
  if(!file){
    return -1;
  }
  begin_op();
  itrunc(file->ip);
  end_op();
  return 0;
}
int sys_fileclose(void* fh){
  struct file* file = (struct file*)fh;
  fileclose(file);
  return 0;
}

int sys_close(int fd){
  if(fd >= NOFILE + 3){
    return -1;
  }
  struct file *file = open_file[fd - 3];
  if(!file){
    return 0;
  }
  int ret = sys_fileclose(file);
  open_file[fd - 3] = 0;
  return ret;
}
static int
isdirempty(struct inode *dp)
{
  int off;
  struct dirent de;

  for(off=2*sizeof(de); off<dp->size; off+=sizeof(de)){
    if(readi(dp,(uint64)&de, off, sizeof(de)) != sizeof(de)){
      // panic("isdirempty: readi");
      // how to panic?
    }
    if(de.inum != 0)
      return 0;
  }
  return 1;
}
int sys_unlink(const char* path){
  struct inode *ip, *dp;
  struct dirent de;
  char name[DIRSIZ];
  uint off;
  begin_op();
  if((dp = nameiparent(path,name)) == 0){
    end_op();
    return -1;
  }
  ilock(dp);
  if(namecmp(name, ".") == 0 || namecmp(name, "..") == 0){
    goto bad;
  }
  if((ip = dirlookup(dp,name,&off)) == 0){
    goto bad;
  }
  ilock(ip);
  if(ip->nlink < 1){
    //should panic? but how?
    goto bad;
  }
  if(ip->type == T_DIR && !isdirempty(ip)){
    iunlockput(ip);
    goto bad;
  }
  memset(&de, 0, sizeof(de));
  if(writei(dp,(uint64)&de, off, sizeof(de)) != sizeof(de)){
    //panic
    goto bad;
  }
  if(ip->type == T_DIR){
    dp->nlink --;
    iupdate(dp);
  }
  iunlockput(dp);
  ip->nlink --;
  iupdate(ip);
  iunlockput(ip);
  end_op();
  return 0;
  bad:
      iunlockput(dp);
      end_op();
      return -1;
}

// static int sys_fileread(void* fh, char* buf, int size){
//   struct file* file = (struct file*)fh;
//   if(file == 0){
//     return -1;
//   }
//   int r = fileread(file,buf,size);
//   file->off += r;
//   return r;
// }

int sys_read(int fd, void *buf, int size){
  if(fd >= NOFILE + 3 || open_file[fd-3] == 0){
    return -1;
  }
  struct file *file = open_file[fd - 3];
  if(!file){
    return 0;
  }
  return fileread(file, buf, size);
}

// int sys_write(void*fh, void* buf, int size){
//   struct file* file = (struct file*)fh;
//   if(file == 0){
//     return -1;
//   }
//   int r = filewrite(file,buf,size);
//   file->off += r;
//   return r;
// }

int sys_write(int fd, void* buf, int size){
  if(fd >= NOFILE + 3 || open_file[fd - 3] == 0){
    return -1;
  }
  struct file *file = open_file[fd-3];
  if(!file){ //FIXME: return 0 or -1
    return 0;
  }
  int r = filewrite(file,buf,size);
  return r;
}

int sys_lseek(int fd, int offset, int whence){
  struct file *file;
  if(fd >= NOFILE + 3 || open_file[fd - 3] == 0){
    //panic
    return -1;
  }
  file = open_file[fd-3];
  if(file == 0){
    return -1;
  }
  switch (whence)
  {
  case SEEK_SET:
    file->off = offset>=0?offset:0;
    break;
  case SEEK_CUR:
    file->off += offset;
    break;
  case SEEK_END:
     ilock(file->ip);
     file->off = file->ip->size + offset;
     iunlock(file->ip);
     break;
  default:
    return -1;
    break;
  }
  return file->off;
}

int sys_mkdir(char *path){
  struct inode *ip;

  begin_op();
  if((ip = create(path, T_DIR, 0, 0)) == 0){
    end_op();
    return -1;
  }
  iunlockput(ip);
  end_op();
  return 0;
}

uint sys_file_size(int fd){
    if(fd >= NOFILE + 3 || open_file[fd - 3] == 0){
    //panic
        return 0;
    }
    struct file *file = open_file[fd-3];
    if(file)
      return file->ip->size;
    else
      return 0;
}

