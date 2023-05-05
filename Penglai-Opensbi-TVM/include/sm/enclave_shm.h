#ifndef __ENCLAVE_SHMEM__
#define __ENCLAVE_SHMEM__
#include <sbi/sbi_types.h>
#include <sbi/sbi_list.h>
#include <sbi/riscv_locks.h>
#define DEFAULT_SHM_META_REGION_SIZE (32*4096)
typedef enum {
    SHM_META_INVALID,
    SHM_META_VALID
}sbi_shm_meta_state;
struct sbi_shm_enclaves
{
    uintptr_t eid;
    struct sbi_dlist link;
};

//FIXME: At this time, we just globally manage all the shared memory info object.
//TODO: semaphore support for synchronization between enclaves.
struct sbi_shm_infop
{
    uintptr_t shm_key;
    // uintptr_t shm_paddr;
    // uintptr_t shm_size;
    uintptr_t shm_flags;
    uintptr_t shm_refcount;
    // spinlock_t sbi_shm_enclaves_lock;
    // struct sbi_shm_enclaves shared_enclaves; // linked enclave ids of enclaves that share this memory region.
    uintptr_t paddr;
    uintptr_t size;
    sbi_shm_meta_state state;
    unsigned int last_free_meta_index;
    int need_destroy;
};

struct sbi_shm_metadata
{
    uintptr_t eid;
    struct vm_area_struct vma;
    struct pm_area_struct pma;
};

struct sbi_shm_des{
    unsigned long ref_count;
    unsigned long shm_size;
};


#endif