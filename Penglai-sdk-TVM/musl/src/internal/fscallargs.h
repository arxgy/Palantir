#define FSOPEN 0
#define FSCLOSE 1
#define FSREAD 2
#define FSWRITE 3
#define FSSTAT 4
#define FSLSEEK 5
#define FSFLUSH 6
#define FTRUNCATE 7
#define UNLINK 8
#define FSMKDIR 9
#define MAXPATH 128
struct open_arg
{
    char path[MAXPATH];
    int mode;
};

struct close_arg{
    int fd;
};

struct lseek_arg
{
    int fd;
    int offset;
    int whence;
};

struct read_arg{
    int fd;
    int size; // this size must <= the size of the buffer
};

struct write_arg{
    int fd;
    int size; // this size must <= the size of the buffer
};

struct ftruncate_arg
{
    int fd;
};

struct unlink_arg
{
    char path[MAXPATH];
};

struct mkdir_arg
{
    char path[MAXPATH];
};

struct stat_arg
{
    int fd;
    char path[MAXPATH];
};

