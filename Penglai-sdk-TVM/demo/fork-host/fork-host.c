#include "penglai-enclave.h"
#include <stdlib.h>
#include <stdlib.h>
#include <pthread.h>

#define MAGIC_SHM_VALUE 11111
#define MAGIC_RELAY_PAGE_VALUE 22222

struct args
{
  unsigned long in;
  int i;
  int fd;
  int shmid;
  unsigned long shm_offset;
  unsigned long shm_size;
};

void* create_enclave(void* args0)
{
  struct args *args = (struct args*)args0;
  unsigned long eid = args->in;
  int i = args->i, ret = 0, fd = args->fd, shmid = args->shmid;
  unsigned long shm_offset = args->shm_offset, shm_size = args->shm_size;

  int mm_arg_id;
  void * mm_arg;
  unsigned long mm_arg_size;
  
  printf("host:%d: enclave run eid %lx\n", i, eid);
  struct PLenclave* enclave = malloc(sizeof(struct PLenclave));
  PLenclave_init(enclave);

  enclave->fd = fd;
  enclave->user_param.eid = eid;
  enclave->user_param.shmid = shmid;
  enclave->user_param.shm_offset = shm_offset;
  enclave->user_param.shm_size = shm_size;
  enclave->eid = eid;
  
  mm_arg_size = 0x1000 * 1;
  mm_arg_id = PLenclave_schrodinger_get(mm_arg_size);
  mm_arg = PLenclave_schrodinger_at(mm_arg_id, 0);

  if(mm_arg != (void*)-1)
    ((int*)mm_arg)[0] = MAGIC_RELAY_PAGE_VALUE;
  
  char str_num[15];
  sprintf(str_num, "test-enclave%d", i);
  strcpy(enclave->user_param.name, str_num);

  PLenclave_attest(enclave, 0);

  if(mm_arg_id > 0 && mm_arg)
    PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);

  int run_result;
  while (run_result = PLenclave_run(enclave))
  {
    switch (run_result)
    {
      case RETURN_USER_RELAY_PAGE:
        *(int*)mm_arg = 2;
        PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
        break;
      default:
        printf("[ERROR] host: run_result val is wrong!\n");
        goto free_enclave;
    }
  }

free_enclave:
  PLenclave_schrodinger_dt(mm_arg_id, mm_arg);
  PLenclave_schrodinger_ctl(mm_arg_id);
  free(enclave);
  pthread_exit((void*)0); 
}

int main(int argc, char** argv)
{
  if(argc <= 1)
    printf("Please input the enclave ELF file name\n");

  int thread_num = 1;
  if(argc == 3)
  {
    thread_num = atoi(argv[2]);
    if(thread_num <= 0)
    {
      printf("error number\n");
      return -1;
    }
  }

  pthread_t* threads = (pthread_t*)malloc(thread_num * sizeof(pthread_t));
  struct args* args = (struct args*)malloc(thread_num * sizeof(struct args));

  struct elf_args* enclaveFile = malloc(sizeof(struct elf_args));
  char * eappfile = argv[1];
  elf_args_init(enclaveFile, eappfile);
  
  if(!elf_valid(enclaveFile))
  {
    printf("error when initializing enclaveFile\n");
    goto out;
  }
  
  struct PLenclave* enclave = malloc(sizeof(struct PLenclave)); 
  struct enclave_args* params = malloc(sizeof(struct enclave_args));
  PLenclave_init(enclave);
  enclave_args_init(params);

  unsigned long shm_size = 0x1000 * 4;
  int shmid = PLenclave_shmget(shm_size);
  void* shm = PLenclave_shmat(shmid, 0);
  if(shm != (void*)-1)
    ((int*)shm)[0] = MAGIC_SHM_VALUE;

  params->shmid = shmid;
  params->shm_offset = 0;
  params->shm_size = shm_size;
  //Mark the enclave as a shaodw enclave
  params->type = SHADOW_ENCLAVE;

  if(PLenclave_create(enclave, enclaveFile, params) < 0 )
  {
    printf("host: failed to create enclave\n");
    pthread_exit((void*)0);
  }

  unsigned long eid = enclave->user_param.eid;
  int fd = enclave->fd;
  for(int i=0; i< thread_num; ++i)
  {
    args[i].in = eid;
    args[i].i = i + 1;
    args[i].fd = fd;
    args[i].shmid = enclave->user_param.shmid;
    args[i].shm_offset = enclave->user_param.shm_offset;
    args[i].shm_size = enclave->user_param.shm_size;
    pthread_create(&threads[i], NULL, create_enclave, (void*)&(args[i]));
  }

  for(int i =0; i< thread_num; ++i)
  {
    pthread_join(threads[i], (void**)0);
  }

  PLenclave_destruct(enclave);
  PLenclave_destroy(enclave);

out:
  elf_args_destroy(enclaveFile);
  free(enclaveFile);
  free(threads);
  free(args);
  free(enclave);
  free(params);

  return 0;
}
