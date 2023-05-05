#ifndef _KEY_H
#define _KEY_H
#include "sbi/sbi_types.h"

#define KEY_SIZE_BYTES 32

int m_derive_key(int key_type, unsigned char *enclave_hash, int key_size, char *okey);
uintptr_t platform_getrand(char* buff, uintptr_t size);

#endif

