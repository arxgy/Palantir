#include "penglai-enclave.h"
#include <stdlib.h>
#include <pthread.h>

#define MAGIC_SHM_VALUE 11111
#define MAGIC_RELAY_PAGE_VALUE 22222
struct args
{
  void* in;
  int i;
};

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

void* create_enclave(void* args0)
{
  struct args *args = (struct args*)args0;
  void* in = args->in;
  int i = args->i;
  int ret = 0, result = 0;
  unsigned long total_cycle = 0, begin_cycle;

  struct PLenclave* enclave = malloc(sizeof(struct PLenclave));
  struct enclave_args* params = malloc(sizeof(struct enclave_args));
  PLenclave_init(enclave);
  enclave_args_init(params);

  struct elf_args *enclaveFile = (struct elf_args *)in;

  unsigned long shm_size = 0x1000 * 1;
  int shmid = PLenclave_shmget(shm_size);
  void* shm = PLenclave_shmat(shmid, 0);
  if(shm != (void*)-1)
  {
    ((int*)shm)[0] = MAGIC_SHM_VALUE;
  }
  params->shmid = shmid;
  params->shm_offset = 0;
  params->shm_size = shm_size;
  
  unsigned long mm_arg_size = 0x1000 * 1;
  int mm_arg_id = PLenclave_schrodinger_get(mm_arg_size);
  void* mm_arg = PLenclave_schrodinger_at(mm_arg_id, 0);
  if(mm_arg != (void*)-1)
  {
    ((int*)mm_arg)[0] = MAGIC_RELAY_PAGE_VALUE;
  }
  char str_num[15];
  sprintf(str_num, "test-enclave%d", i);
  strcpy(params->name, str_num);
  /* Try to launch a PE. */
  params->type = PRIVIL_ENCLAVE;
  
  begin_cycle = get_cycle();
  if(PLenclave_create(enclave, enclaveFile, params) < 0)
  {
    printf("host:%d: failed to create enclave\n", i);
  }
  else
  {
    printf("\nenclave [%u] is created\n", enclave->eid);
    PLenclave_attest(enclave, 0);
    if(mm_arg_id > 0 && mm_arg)
      PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    while (result = PLenclave_run(enclave))
    {
      total_cycle += get_cycle()-begin_cycle;
      switch (result)
      {
        case RETURN_USER_RELAY_PAGE:
          ((int*)mm_arg)[0] = 0;
          printf("[host] looping...\n");
          PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
          break;
        default:
        {
          printf("[ERROR] host: result %d val is wrong!\n", result);
          goto free_enclave;
        }
      }
      begin_cycle = get_cycle();
    }
  }
  PLenclave_destruct(enclave);
  total_cycle += get_cycle()-begin_cycle;
  printf("host: total_cycle: [%lu]\n", total_cycle);

free_enclave:  
  PLenclave_shmdt(shmid, shm);
  PLenclave_shmctl(shmid);
  PLenclave_schrodinger_dt(mm_arg_id, mm_arg);
  PLenclave_schrodinger_ctl(mm_arg_id);
  free(enclave);
  free(params);
  pthread_exit((void*)0);
}

int main(int argc, char** argv)
{
  if(argc <= 1)
  {
    printf("Please input the enclave ELF file name\n");
  }

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
  char* eappfile = argv[1];
  elf_args_init(enclaveFile, eappfile);
  
  if(!elf_valid(enclaveFile))
  {
    printf("error when initializing enclaveFile\n");
    goto out;
  }

  for(int i=0; i< thread_num; ++i)
  {
    args[i].in = (void*)enclaveFile;
    args[i].i = i + 1;
    pthread_create(&threads[i], NULL, create_enclave, (void*)&(args[i]));
  }

  for(int i =0; i< thread_num; ++i)
  {
    pthread_join(threads[i], (void**)0);
  }
  printf("host: after exit the thread\n");
out:
  elf_args_destroy(enclaveFile);
  free(enclaveFile);
  free(threads);
  free(args);

  return 0;
}
