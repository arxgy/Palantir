#ifndef _PENGLAI_ENCLAVE_PERSISTENCY_
#define _PENGLAI_ENCLAVE_PERSISTENCY_
#define FS_INIT_SIZE_ORDER (10)  // PERSISTENCY_FILE initialize with 4M size
#define BSIZE (4096)
#define PERSISTENCY_FILE_PATH ("/mnt/persistencty_file")
int penglai_fs_persistency_init(struct file *filep, unsigned long args);
int penglai_outer_init(unsigned long shm_id_p);
int penglai_outer_read(unsigned long sec);
int penglai_outer_write(unsigned long sec);
#endif