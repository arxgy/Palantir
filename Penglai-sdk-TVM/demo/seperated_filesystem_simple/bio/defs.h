#ifndef __BIO_DEFS__
#define __BIO_DEFS__
struct buf;
//bio.c
struct buf* bread(uint,uint);
void   bwrite(struct buf*);
void brelse(struct buf*);
void binit();
void print_buf_list();
//log.c
void   begin_op();
void   end_op();
void   log_write(struct buf*);
void   initlog(int,uint,uint);
#endif