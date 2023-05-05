#include <linux/fs.h>
#include <asm/uaccess.h>
#include "penglai-enclave-persistency.h"
#include "penglai-enclave-driver.h"
#include "penglai-shm.h"
#include "penglai-enclave-driver.h"
static struct file* penglai_outer_file = NULL;
static int fs_shm_id = -1;
static unsigned long fs_shm_size = 0;
static unsigned long fs_shm_va = 0;
//TODO: read write should add lock later
int penglai_outer_open(const char *path, int flags, int mode){
    penglai_outer_file = filp_open(path, flags, mode);
    if(IS_ERR(penglai_outer_file)){
        penglai_eprintf("open persistent file failed\n");
        return -1;
    }
    return 0;
}

//FIXME: modify shm structure need to lock or not?
int penglai_outer_init(unsigned long shm_id_ptr){
    loff_t pos = 0;
    char *tmp_buf;
    struct kstat stat;
    size_t write_size;
    struct penglai_shm * shm;
    fs_shm_id = *((int*)(shm_id_ptr));
    if(penglai_outer_file){ //already inited
        shm = penglai_shm_find(fs_shm_id);
        fs_shm_size = shm->size;
        fs_shm_va = shm->vaddr;
        return 0;
    }
    if(fs_shm_id < MIN_PENGLAI_SHMID || fs_shm_id > MAX_PENGLAI_SHMID){
        penglai_eprintf("invalid shm_id for fs persistency\n");
        fs_shm_id = -1;
        return -1;
    }
    shm = penglai_shm_find(fs_shm_id);
    fs_shm_size = shm->size;
    fs_shm_va = shm->vaddr;
    //need not using mmap on kernel module
    if(penglai_outer_open(PERSISTENCY_FILE_PATH, O_CREAT|O_RDWR, 0644) < 0){
        return -1;
    }

    vfs_stat(PERSISTENCY_FILE_PATH, &stat);
    if(stat.size == 0){
        tmp_buf = (char *)penglai_get_free_pages(GFP_KERNEL, FS_INIT_SIZE_ORDER);
        if(!tmp_buf){
            penglai_eprintf("error when penglai_outer_init\n");
            filp_close(penglai_outer_file,NULL);
            penglai_outer_file = NULL;
            return -1;
        }
        memset(tmp_buf, 0, 1 << (12+FS_INIT_SIZE_ORDER));
        write_size = kernel_write(penglai_outer_file, tmp_buf, 1 << (12+FS_INIT_SIZE_ORDER),&pos);
        if(write_size != 1 << (12+FS_INIT_SIZE_ORDER)){
            penglai_eprintf("ourter_init kernel_write failed\n");
        }
        free_pages((unsigned long)tmp_buf,FS_INIT_SIZE_ORDER);
    }
    return 0;
}

// TODO: optimize the performance of persistency
//TODO:  Now, every read/write to a data block will cause an out call, this can be optimized, and how?
int penglai_outer_read(unsigned long sec){
    size_t read_size;
    loff_t pos;
    if(penglai_outer_file == NULL || fs_shm_va == 0 || fs_shm_size == 0 ){
        penglai_eprintf("penglai_outer didn't init successfully, persistency unavailable\n");
        return -1;
    }

    pos = sec * BSIZE;
    read_size = kernel_read(penglai_outer_file, (char*)fs_shm_va, BSIZE, &pos);
    if(read_size != BSIZE){
        // just write dirty data to file as a manner to enlarge space
        memset((char*)fs_shm_va, 0, BSIZE);
        kernel_write(penglai_outer_file,(char*)fs_shm_va, BSIZE, &pos);
        // then just return the dirty content to driver, driver should understand this.
    }
    return 0;

}
// FIXME: just assume will write the block ? is it reasonable?
int penglai_outer_write(unsigned long sec){
    // mm_segment_t fs;
    size_t write_size;
    loff_t pos;
    if(penglai_outer_file == NULL || fs_shm_va == 0 || fs_shm_size == 0 ){
        penglai_eprintf("penglai_outer didn't init successfully, persistency unavailable\n");
        return -1;
    }

    pos = sec * BSIZE;
    write_size = kernel_write(penglai_outer_file,(char*)fs_shm_va, BSIZE, &pos);
    if(write_size != BSIZE){
        penglai_eprintf("write error\n");
    }
    return 0;
}

int penglai_fs_persistency_init(struct file *filep, unsigned long args){
    return penglai_outer_init(args);
}