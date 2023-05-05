#ifndef _PENGLAI_ENCLAVE_OCALL
#define _PENGLAI_ENCLAVE_OCALL
#include "penglai-enclave-ioctl.h"

int penglai_enclave_ocall(enclave_instance_t *enclave_instance, enclave_t *enclave, int resume_id, int isShadow);
#endif