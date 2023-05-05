#include "lfs.h"
#include "lfsram.h"
static char ramdisk[128][4096];
int ram_read(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, void* buffer, lfs_size_t size){
    memcpy(buffer,ramdisk[block] + off,size);
    return 0;
}

int ram_prog(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, void* buffer, lfs_size_t size){
    memcpy(ramdisk[block] + off, buffer, size);
    return 0;
}

int ram_erase(const struct lfs_config *c, lfs_block_t block){
    return 0;
}

int ram_sync(const struct lfs_config *c){
    return 0;
}