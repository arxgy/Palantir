#include "param.h"
#include "stdlib.h"
pthread_mutex_t mutex;

void enclave_args_init(struct enclave_args* enclave_args)
{
  enclave_args->type = NORMAL_ENCLAVE;
  enclave_args->stack_size = DEFAULT_STACK_SIZE;
  enclave_args->shmid = 0;
  enclave_args->shm_offset = 0;
  enclave_args->shm_size = 0;
}
