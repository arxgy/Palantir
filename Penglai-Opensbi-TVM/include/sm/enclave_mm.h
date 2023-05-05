#ifndef _ENCLAVE_MM_H
#define _ENCLAVE_MM_H

#include "sbi/sbi_types.h"
#include "sm/enclave.h"

struct mm_region_list_t
{
  uintptr_t paddr;
  unsigned long size;
  struct mm_region_list_t *next;
};

int check_and_set_secure_memory(unsigned long paddr, unsigned long size);
int __free_secure_memory(unsigned long paddr, unsigned long size);
int free_secure_memory(unsigned long paddr, unsigned long size);

uintptr_t mm_init(uintptr_t paddr, unsigned long size);
void* mm_alloc(unsigned long req_size, unsigned long* resp_size);
int mm_free(void* paddr, unsigned long size);

int grant_enclave_access(struct enclave_t* enclave);
int retrieve_enclave_access(struct enclave_t *enclave);

#endif /* _ENCLAVE_MM_H */
