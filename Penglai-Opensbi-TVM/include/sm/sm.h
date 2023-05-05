#ifndef _SM_H
#define _SM_H

#include "sbi/sbi_types.h"
#include "sm/enclave_args.h"
#include "sm/ipi.h"

#define SM_BASE 0x80000000UL
#define SM_SIZE 0x200000UL

//SBI_CALL NUMBERS
#define SBI_SET_PTE            101
#define SBI_SM_INIT            100
#define SBI_CREATE_ENCLAVE      99
#define SBI_ATTEST_ENCLAVE      98
#define SBI_RUN_ENCLAVE         97
#define SBI_STOP_ENCLAVE        96
#define SBI_RESUME_ENCLAVE      95
#define SBI_DESTROY_ENCLAVE     94
#define SBI_MEMORY_EXTEND       92
#define SBI_MEMORY_RECLAIM      91
#define SBI_CREATE_SERVER_ENCLAVE         90
#define SBI_DESTROY_SERVER_ENCLAVE        89
#define SBI_DESTROY_SHADOW_ENCLAVE        79

#define SBI_SM_DEBUG_PRINT               88
#define SBI_RUN_SHADOW_ENCLAVE           87
#define SBI_CREATE_SHADOW_ENCLAVE        86

#define SBI_SCHRODINGER_INIT             85
#define SBI_SM_PT_AREA_SEPARATION        83
#define SBI_SM_SPLIT_HUGE_PAGE           82
#define SBI_SM_MAP_PTE                   81
#define SBI_ATTEST_SHADOW_ENCLAVE        80

//SBI_SET_PTE reason
#define SBI_SET_PTE_ONE          1
#define SBI_PTE_MEMSET           2
#define SBI_PTE_MEMCPY           3
#define SBI_SET_PTE_BATCH_ZERO   4
#define SBI_SET_PTE_BATCH_SET    5

//Error code of enclave sbi call
#define ENCLAVE_ERROR           -1
#define ENCLAVE_NO_MEM          -2
#define ENCLAVE_ATTESTATION     -3

//Enclave exit reason 
#define ENCLAVE_SUCCESS          0
#define ENCLAVE_TIMER_IRQ        1
#define ENCLAVE_OCALL            2
#define ENCLAVE_YIELD            3

//Function id of resume reason
#define RESUME_FROM_TIMER_IRQ    0
#define RESUME_FROM_STOP         1
#define RESUME_FROM_OCALL        2

#define SBI_LEGAL_MAX            100UL

//Enclave ocall reason
#define SBI_EXIT_ENCLAVE         99
#define SBI_ENCLAVE_OCALL        98
#define SBI_ACQUIRE_SERVER       97
#define SBI_CALL_ENCLAVE         96
#define SBI_ENCLAVE_RETURN       95
#define SBI_ASYN_ENCLAVE_CALL    93
#define SBI_SPLIT_MEM_REGION     92
#define SBI_GET_CALLER_ID        91
#define SBI_GET_ENCLAVE_ID       90
#define SBI_YIELD                89
#define SBI_GET_REPORT           94


#define SBI_SHM_ATTACH           84
#define SBI_SHM_STAT             83


#define SBI_GET_KEY              88

//Enclave ocall error number
#define SYS_NULL                 0

//Enclave ocall number
#define OCALL_MMAP                   1
#define OCALL_UNMAP                  2
#define OCALL_SYS_WRITE              3
#define OCALL_SBRK                   4
#define OCALL_READ_SECT              5
#define OCALL_WRITE_SECT             6
#define OCALL_RETURN_RELAY_PAGE      7

#define OCALL_SHM_GET                9
#define OCALL_SHM_DETACH             10
#define OCALL_SHM_DESTROY            11
#define OCALL_SHM_EXTEND_MEMORY      12

#define OCALL_GETRANDOM              8

typedef int page_meta;
#define NORMAL_PAGE                      ((page_meta)0x7FFFFFFF)
#define ZERO_MAP_PAGE                    ((page_meta)0x7FFFFFFE)
#define PRIVATE_PAGE                     ((page_meta)0x80000000)
#define IS_PRIVATE_PAGE(meta)            (((page_meta)meta) & PRIVATE_PAGE)
#define IS_PUBLIC_PAGE(meta)             (!IS_PRIVATE_PAGE(meta))
#define IS_ZERO_MAP_PAGE(meta)           (((page_meta)meta & NORMAL_PAGE) == ZERO_MAP_PAGE)
#define IS_SCHRODINGER_PAGE(meta)        (((page_meta)meta & NORMAL_PAGE) != NORMAL_PAGE)
#define MAKE_PRIVATE_PAGE(meta)          ((page_meta)meta | PRIVATE_PAGE)
#define MAKE_PUBLIC_PAGE(meta)           ((page_meta)meta & NORMAL_PAGE)
#define MAKE_ZERO_MAP_PAGE(meta)         (((page_meta)meta & PRIVATE_PAGE) | ZERO_MAP_PAGE)
#define MAKE_SCHRODINGER_PAGE(pri, pos)  (pri ? \
    (PRIVATE_PAGE | ((page_meta)pos & NORMAL_PAGE)) \
    : ((page_meta)pos & NORMAL_PAGE))
#define SCHRODINGER_PTE_POS(meta)        (IS_ZERO_MAP_PAGE(meta) ? -1 : ((int)meta & (int)0x7FFFFFFF))

struct pt_area_batch_t {
	unsigned long ptep_base;
	union {
		unsigned long ptep_size;
		unsigned long ptep_entry;
	} entity;
};

void sm_init();

int enable_enclave();
//remember to acquire mbitmap_lock before using these functions
int contain_private_range(uintptr_t pfn, uintptr_t pagenum);
int test_public_range(uintptr_t pfn, uintptr_t pagenum);
int set_private_range(uintptr_t pfn, uintptr_t pagenum);
int set_public_range(uintptr_t pfn, uintptr_t pagenum);
int unmap_mm_region(unsigned long paddr, unsigned long size);
int remap_mm_region(unsigned long paddr, unsigned long size);

int check_in_enclave_world();

// Called by host
// Penglai-specific operations
uintptr_t sm_sm_init(uintptr_t pt_area_base, uintptr_t pt_area_size, uintptr_t mbitmap_base, uintptr_t mbitmap_size, uintptr_t _module_installed_ptr);
uintptr_t sm_pt_area_separation(uintptr_t pgd_order, uintptr_t pmd_order);
uintptr_t sm_set_pte(uintptr_t flag, uintptr_t* pte_addr, uintptr_t pte_src, uintptr_t size);
uintptr_t sm_map_pte(uintptr_t* pte, uintptr_t* new_pte_addr);
uintptr_t sm_mm_init(uintptr_t paddr, uintptr_t size);
uintptr_t sm_mm_extend(uintptr_t paddr, uintptr_t size);
uintptr_t sm_schrodinger_init(uintptr_t paddr, uintptr_t size);

// Enclave-related operations
uintptr_t sm_create_enclave(uintptr_t enclave_create_args);
uintptr_t sm_attest_enclave(uintptr_t enclave_id, uintptr_t report, uintptr_t nonce);
uintptr_t sm_run_enclave(uintptr_t *regs, uintptr_t enclave_id, uintptr_t enclave_run_arg);
uintptr_t sm_stop_enclave(uintptr_t *regs, uintptr_t enclave_id);
uintptr_t sm_resume_enclave(uintptr_t *regs, uintptr_t enclave_id, uintptr_t resume_func_id);
uintptr_t sm_destroy_enclave(uintptr_t *regs, uintptr_t enclave_id);

// Server enclave-related operations
uintptr_t sm_create_server_enclave(uintptr_t enclave_create_args);
uintptr_t sm_destroy_server_enclave(uintptr_t *regs, uintptr_t enclave_id);

// Shadow enclave-related operations
uintptr_t sm_create_shadow_enclave(uintptr_t enclave_create_args);
uintptr_t sm_run_shadow_enclave(uintptr_t *regs, uintptr_t enclave_id, uintptr_t shadow_enclave_run_args);
uintptr_t sm_attest_shadow_enclave(uintptr_t enclave_id, uintptr_t report, uintptr_t nonce);
uintptr_t sm_destroy_shadow_enclave(uintptr_t *regs, uintptr_t enclave_id);

// Called by enclave
uintptr_t sm_enclave_ocall(uintptr_t *regs, uintptr_t ocall_func_id, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2);
uintptr_t sm_exit_enclave(uintptr_t *regs, uintptr_t retval);
// IPC interfaces for enclaves
uintptr_t sm_server_enclave_acquire(uintptr_t *regs, uintptr_t server_name);
uintptr_t sm_call_enclave(uintptr_t *regs, uintptr_t enclave_id, uintptr_t arg);
uintptr_t sm_asyn_enclave_call(uintptr_t *regs, uintptr_t enclave_name, uintptr_t arg);
uintptr_t sm_enclave_return(uintptr_t *regs, uintptr_t arg);
uintptr_t sm_get_report(uintptr_t *regs, char* name, uintptr_t *report, uintptr_t nonce);
uintptr_t sm_get_key(uintptr_t *regs, uintptr_t key_type, uintptr_t *key, uintptr_t key_size);

uintptr_t sm_get_caller_id(uintptr_t *regs);
uintptr_t sm_get_enclave_id(uintptr_t *regs);
uintptr_t sm_split_mem_region(uintptr_t *regs, uintptr_t mem_addr, uintptr_t mem_size, uintptr_t split_addr);

// Called when timer irq
uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc);
uintptr_t sm_handle_yield(uintptr_t *regs);

// Debug
uintptr_t sm_print(uintptr_t paddr, uintptr_t size);

#endif /* _SM_H */
