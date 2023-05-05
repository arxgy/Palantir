#include "types.h"
#include "structure.h"
#include "eapp.h"
#include "print.h"
#include "buf.h"
#include <stdlib.h>
#include <string.h>
#define min(a,b) (((a)<(b))?(a):(b))
static struct superblock init_sb;
static int inited;
static unsigned long shm_addr;
static unsigned long shm_size;
static uint freeblock;
// TODO: do the encrypt and decrypt in wsect and rsect later
int wsect(uint sec, void* buf){
    if(!inited){
        return -1;
    }
    memcpy((void*)shm_addr, buf, BSIZE);
    int ret = eapp_persistency_write_sec(sec);
    return ret;
}

int rsect(uint sec, void* buf){
    int ret;
    if(!inited){
        return -1;
    }
    ret = eapp_persistency_read_sec(sec);
    if(!ret){
        memcpy(buf, (void*)shm_addr,BSIZE);
    }
    return ret;
}

void rinode(uint inum, struct dinode *ip){
    char buf[BSIZE];
    uint bn;
    int status;
    struct dinode *dip;
    bn = IBLOCK(inum);
    status = rsect(bn, buf);
    if(status){
        eapp_print("[Persistency]: rsect failed in rinode\n");
    }
    dip = ((struct dinode*)buf) + (inum % IPB);
    *ip = *dip;
}

void winode(uint inum, struct dinode *ip){
    char buf[BSIZE];
    int status;
    uint bn;
    struct dinode *dip;
    bn = IBLOCK(inum);
    status = rsect(bn, buf);
    if(status){
        eapp_print("[Persistency]: rsect failed in winode\n");
    }
    dip = ((struct dinode*)buf) + (inum % IPB);
    *dip = *ip;
    status = wsect(bn, buf);
    if(status){
        eapp_print("[Persistency]: wsect failed in winiode\n");
    }

}

uint ialloc(ushort type){
    static uint freeiode = 1;
    uint inum = freeiode ++;
    struct dinode di;
    memset(&di, 0, sizeof(struct dinode));
    di.type = type;
    di.size = 0;
    di.nlink = 1;
    winode(inum, &di);
    return inum;
}

void balloc(int used){
    uchar buf[BSIZE] = {0};
    int i;
    bzero(buf, BSIZE);
    for(i = 0; i < used; i++){
      buf[i/8] = buf[i/8] | (0x1 << (i%8));
    }
    wsect(BMAPSTART, buf);
}

// FIXME: unnecessary to implement doublely indirect here because won't append much content here when init
void iappend(uint inum, void *xp, int n){
    char *p = (char*)xp;
    uint fbn, off, n1;
    struct dinode din;
    char buf[BSIZE];
    uint indirect[NINDIRECT] = {0};
    uint x;
    rinode(inum, &din);
    off = din.size;
    while (n>0)
    {
        fbn = off / BSIZE;
        if(fbn < NDIRECT){
            if(din.addrs[fbn] == 0){
                din.addrs[fbn] = freeblock ++;
            }
            x = din.addrs[fbn];
        }
        else{
            if(din.addrs[NDIRECT] == 0){
                din.addrs[NINDIRECT] = freeblock ++;
                wsect(din.addrs[NDIRECT], (char*)indirect);
            }
            x = indirect[fbn-NDIRECT];
        }
        n1 = min(n, (fbn + 1)*BSIZE - off);
        rsect(x, buf);
        memcpy(buf + off - (fbn * BSIZE), p, n1);
        wsect(x, buf);
        n -= n1;
        p += n1;
        off += n1;
    }
    din.size = off;
    winode(inum, &din);
}

void persistency_init(unsigned long *args){
    eapp_print("[eapp]: persistency init\n");
    char buf[BSIZE] = {0};
    int ret;
    shm_addr = args[13];
    shm_size = args[14];
    inited = 1;
    if(!shm_addr || !shm_size){
        eapp_print("[eapp]: No shared memory for persistency\n");
        return;
    }
    ret = rsect(1, buf);
    if(ret){
        inited = 0;
        eapp_print("rsect 1 failed\n");
        return;
    }
    memcpy(&init_sb, buf, sizeof(struct superblock));
    if(init_sb.magic == FSMAGIC && init_sb.size == FSSIZE && init_sb.nlog == LOGSIZE){
        return;
    }
    init_sb.magic = FSMAGIC;
    init_sb.nlog = LOGSIZE;
    init_sb.ninodes = NINODES;
    init_sb.logstart = 2;
    init_sb.inodestart = 2 + LOGSIZE;
    init_sb.bmapstart = BMAPSTART;
    init_sb.size = FSSIZE;
    int nbitmap = FSSIZE/(BSIZE*8) + 1;
    int nmeta = 2 + LOGSIZE + NINODES/IPB + nbitmap + 1;
    init_sb.nblocks = FSSIZE - nmeta;
    memset(buf, 0, BSIZE);
    memcpy(buf, &init_sb, sizeof(struct superblock));
    //FIXME: write superblock out after later
    wsect(1, buf);
    freeblock = nmeta;
    uint rootino = ialloc(T_DIR);
    struct dirent de;
    memset(&de, 0, sizeof(de));
    de.inum = rootino;
    strcpy(de.name,".");
    iappend(rootino, &de, sizeof(de));
    memset(&de, 0, sizeof(de));
    de.inum = rootino;
    strcpy(de.name, "..");
    iappend(rootino,&de, sizeof(de));
    balloc(freeblock);
}


int persistencyrw(struct buf *b){
    int ret = 0;
    if((b->flags & (B_VALID|B_DIRTY)) == B_VALID){
        return -1;
    }
    if(b->blockno >= FSSIZE){
        return -1;
    }
    if(b->flags & B_DIRTY){
        ret = wsect(b->blockno, b->data);
        b->flags &= ~B_DIRTY;
    }
    else{
        ret = rsect(b->blockno, b->data);
    }
    return ret;
} 

int EAPP_ENTRY main(){
    unsigned long *args;
    EAPP_RESERVE_REG;
    if(!inited){
        persistency_init(args);
        if(inited){
            eapp_print("[eapp]: persistency inited successfully\n");
        }
    }
    struct buf *buf = (struct buf*)args[11];
    struct call_enclave_arg_t ret_arg;
    memset(&ret_arg, 0, sizeof(struct call_enclave_arg_t));
    if(!inited){
        ret_arg.resp_val = -1;
    }
    else{
        ret_arg.resp_val = persistencyrw(buf);
    }
    ret_arg.req_vaddr = args[11];
    ret_arg.req_size = args[12];  
    SERVER_RETURN(&ret_arg);

}

