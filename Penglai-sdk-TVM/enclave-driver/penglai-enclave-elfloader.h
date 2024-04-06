#ifndef _PENGLAI_ENCLAVE_ELFLOADER
#define _PENGLAI_ENCLAVE_ELFLOADER
#include <linux/elf.h>
#include <linux/slab.h>
#include "penglai-enclave-page.h"

#ifndef _PENGLAI_ENCLAVE_TYPE
#define _PENGLAI_ENCLAVE_TYPE
typedef enum
{
  NORMAL_ENCLAVE = 0,
  SERVER_ENCLAVE = 1,
  SHADOW_ENCLAVE = 2,
  PRIVIL_ENCLAVE = 3
} enclave_type_t;
#endif

#ifndef _PENGLAI_ENCLAVE_RECORDS
#define _PENGLAI_ENCLAVE_RECORDS
// todo: support merge (continuous address)
typedef struct penglai_data_records
{
  unsigned long sect_vaddr;
  unsigned long sect_size;
  unsigned long sect_content; // pa addr to the section contents.
  unsigned long next_record;
} elf_data_records_t;

// todo: support merge (continuous address)
typedef struct penglai_bss_records
{
  unsigned long sect_vaddr;
  unsigned long sect_size;
  unsigned long next_record;
} elf_bss_records_t;
#endif

int privil_enclave_eapp_loading(
		enclave_mem_t* enclave_mem,  
		void* elf_ptr, 
		unsigned long size, 
		vaddr_t * elf_entry_point, 
		vaddr_t stack_ptr, 
		int stack_size,
        enclave_type_t type,
		unsigned long migrate_stack_pages, 
		elf_data_records_t** data_records_addr, 
		elf_bss_records_t** bss_records_addr
		);
int penglai_enclave_eapp_loading(
		enclave_mem_t* enclave_mem,  
		void* __user elf_ptr, 
		unsigned long size, 
		vaddr_t * elf_entry_point, 
		vaddr_t stack_ptr, 
		int stack_size,
        enclave_type_t type);
int privil_enclave_elfmemsize(void* elf_ptr, int* size);
int penglai_enclave_elfmemsize(void* __user elf_ptr,   int* size);

#endif
