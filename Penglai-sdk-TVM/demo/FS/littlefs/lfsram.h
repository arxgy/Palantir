#ifndef __LFS_RAM_H__
#define __LFS_RAM_H__
int ram_read(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, void* buffer, lfs_size_t size);
int ram_prog(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, void* buffer, lfs_size_t size);
int ram_erase(const struct lfs_config *c, lfs_block_t block);
int ram_sync(const struct lfs_config *c);
#endif