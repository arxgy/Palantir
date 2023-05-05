#ifndef __BIO_INTERFACE__
#define __BIO_INTERFACE__
#define BEGIN_OP 0
#define END_OP 1
#define BREAD 2
#define LOG_WRITE 3
#define BRELSE 4
#define INITLOG 5
#include "types.h"
struct bread_call_arg
{
    unsigned int dev;
    unsigned int blockno;
};

struct initlog_arg
{
    unsigned int dev;
    uint logstart;
    uint nlog;
};


#endif