#include "penglai-enclave.h"
#include <stdlib.h>
#include <pthread.h>

#define MAGIC_SHM_VALUE 11111
#define MAGIC_RELAY_PAGE_VALUE 22222

unsigned long create_time = 0, attest_time = 0;
unsigned long primitive_create_time = 0, primitive_attest_time = 0;
struct args
{
  void* in;
  int i;
};

void* create_enclave(void* args0)
{
  
  struct args *args = (struct args*)args0;
  void* in = args->in;
  int i = args->i;
  int ret = 0, result = 0;
  

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

  unsigned long create_start, create_end, attest_start, attest_end;
  asm volatile("rdcycle %0" : "=r"(create_start));



  //int res = PLenclave_create(enclave, enclaveFile, params);
  int res = 0;

  if(enclave->fd < 0)
  {
    fprintf(stderr,"LIB: PLenclave_create: enclave hasn't be initialized yet\n");
    res = -1;
  }

  if(!enclaveFile)
  {
    fprintf(stderr,"LIB: PLenclave_create: elffile does not exist\n");
    res = -1;
  }

  enclave->elffile = enclaveFile;
  enclave->user_param.elf_ptr = (unsigned long)(enclaveFile->ptr);
  enclave->user_param.elf_size = enclaveFile->size;
  enclave->user_param.stack_size = params->stack_size;
  if(params->type == SHADOW_ENCLAVE)
    enclave->user_param.stack_size = 0;
  enclave->user_param.shmid = params->shmid;
  enclave->user_param.shm_offset = params->shm_offset;
  enclave->user_param.shm_size = params->shm_size;
  enclave->user_param.type = params->type;
  enclave->user_param.migrate_arg = 0;
  enclave->user_param.migrate_stack_pages = 0;
  memcpy(enclave->user_param.name, params->name, NAME_LEN);
  if(enclave->user_param.elf_ptr == 0 || enclave->user_param.elf_size <= 0)
  {
    fprintf(stderr, "LIB: PLencalve_create: ioctl create enclave: elf_ptr is NULL\n");
    res = -1;
  }
  unsigned long primitive_create_start,primitive_create_end;
  asm volatile("rdcycle %0" : "=r"(primitive_create_start));
  ret = ioctl(enclave->fd, PENGLAI_ENCLAVE_IOC_CREATE_ENCLAVE, &(enclave->user_param));
  asm volatile("rdcycle %0" : "=r"(primitive_create_end));
  primitive_create_time += (primitive_create_end - primitive_create_start);
  if(ret < 0)
  {
    fprintf(stderr, "LIB: PLenclave_create: ioctl create enclave is failed\n");
    res = -1;
  }

  enclave->eid = enclave->user_param.eid;
  res =  0;



  asm volatile("rdcycle %0" : "=r"(create_end));
  //printf("host creating 1 enclave costs %ld cycles\n",create_end - create_start);
  create_time += (create_end - create_start);
  
  
  if(res < 0)
  {
    printf("host:%d: failed to create enclave\n", i);
  }
  else
  { 
    
    
    asm volatile("rdcycle %0" : "=r"(attest_start));

    //PLenclave_attest(enclave, 0);
    int ret = 0;
    enclave->attest_param.isShadow = enclave->user_param.isShadow;
    enclave->attest_param.eid = enclave->eid;
    enclave->attest_param.nonce = 0;
    unsigned long primitive_attest_start,primitive_attest_end;
    asm volatile("rdcycle %0" : "=r"(primitive_attest_start));
    ret = ioctl(enclave->fd, PENGLAI_ENCLAVE_IOC_ATTEST_ENCLAVE, &(enclave->attest_param));
    asm volatile("rdcycle %0" : "=r"(primitive_attest_end));
    primitive_attest_time += (primitive_attest_end - primitive_attest_start);

    if (enclave->user_param.isShadow) {
      printf("\nAttesting: is shadow\n");
    } else {
      printf("\nAttesting: is normal\n");
    }
    if(ret < 0)
    {
      fprintf(stderr, "LIB: ioctl attest enclave is failed ret %d \n", ret);
    }




    asm volatile("rdcycle %0" : "=r"(attest_end));
    //printf("host attesting 1 enclave costs %ld cycles\n",attest_end - attest_start);
    attest_time += (attest_end - attest_start);
    if(mm_arg_id > 0 && mm_arg)
      PLenclave_set_mem_arg(enclave, mm_arg_id, 0, mm_arg_size);
    while (result = PLenclave_run(enclave))
    {
      switch (result)
      {
        case RETURN_USER_RELAY_PAGE:
          ((int*)mm_arg)[0] = 0;
          PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
          break;
        default:
        {
          printf("[ERROR] host: result %d val is wrong!\n", result);
          goto free_enclave;
        }
      }
    }
  }
  PLenclave_destruct(enclave);
  printf("host: PLenclave run is finish \n");

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

  int thread_num = 100;

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
  printf("host create 100 enclave costs %ld cycles\n",create_time);
  printf("host attesting 100 enclave costs %ld cycles\n",attest_time);
  printf("[primitive] host creating 100 enclave costs %ld cycles\n",primitive_create_time);
  printf("[primitive] host attesting 100 enclave costs %ld cycles\n",primitive_attest_time);
  


  printf("host: after exit the thread\n");
out:
  elf_args_destroy(enclaveFile);
  free(enclaveFile);
  free(threads);
  free(args);

  return 0;
}
