#include "penglai-enclave.h"
#include <stdlib.h>
#include <string.h>

#define MAGIC_SHM_VALUE 11111
#define MAGIC_RELAY_PAGE_VALUE 22222

void printHex(unsigned char *c, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		printf("0x%02X, ", c[i]);
		if ((i%4) == 3)
		    printf(" ");

		if ((i%16) == 15)
		    printf("\n");
	}
	if ((i%16) != 0)
		printf("\n");
}

int main(int argc, char** argv)
{
  struct elf_args* server_enclaveFile = NULL;
  struct PLenclave* server_enclave = NULL;
  struct enclave_args* server_params = NULL;
  struct elf_args* server1_enclaveFile = NULL;
  struct PLenclave* server1_enclave = NULL;
  struct enclave_args* server1_params = NULL;
  struct elf_args* caller_enclaveFile = NULL;
  struct PLenclave* caller_enclave = NULL;
  struct enclave_args* caller_params = NULL;
  if(argc < 3)
  {
    printf("Usage: ./test-caller name_of_caller name_of_server ..\n");
  }

server:
  server_enclaveFile = malloc(sizeof(struct elf_args));
  char *server_eappfile = argv[2];
  elf_args_init(server_enclaveFile, server_eappfile);
  
  if(!elf_valid(server_enclaveFile))
  {
    printf("host:error when initializing server_enclaveFile\n");
    goto out;
  }

  server_enclave = malloc(sizeof(struct PLenclave));
  server_params = malloc(sizeof(struct enclave_args));
  PLenclave_init(server_enclave);
  enclave_args_init(server_params);
  strcpy(server_params->name, "test-server");
  server_params->type = SERVER_ENCLAVE;

  if(PLenclave_create(server_enclave, server_enclaveFile, server_params) < 0)
  {
    printf("host:failed to create server_enclave\n");
    goto out;
  }

  if(argc == 3)
    goto caller;

server1:
  server1_enclaveFile = malloc(sizeof(struct elf_args));
  char *server1_eappfile = argv[3];
  elf_args_init(server1_enclaveFile, server1_eappfile);
  
  if(!elf_valid(server1_enclaveFile))
  {
    printf("host:error when initializing server1_enclaveFile\n");
    goto out;
  }

  server1_enclave = malloc(sizeof(struct PLenclave));
  server1_params = malloc(sizeof(struct enclave_args));
  PLenclave_init(server1_enclave);
  enclave_args_init(server1_params);
  strcpy(server1_params->name, "test-server1");
  server1_params->type = SERVER_ENCLAVE;

  if(PLenclave_create(server1_enclave, server1_enclaveFile, server1_params) < 0 )
  {
    printf("host:failed to create server1_enclave\n");
    goto out;
  }


caller:
  caller_enclaveFile = malloc(sizeof(struct elf_args));
  char *caller_eappfile = argv[1];
  elf_args_init(caller_enclaveFile, caller_eappfile);
  
  if(!elf_valid(caller_enclaveFile))
  {
    printf("host:error when initializing caller_enclaveFile\n");
    goto out;
  }

  caller_enclave = malloc(sizeof(struct PLenclave));
  caller_params = malloc(sizeof(struct enclave_args));
  PLenclave_init(caller_enclave);
  enclave_args_init(caller_params);

  // Assign the shared memory for enclave
  unsigned long shm_size = 0x1000 * 4;
  int shmid = PLenclave_shmget(shm_size);
  void* shm = PLenclave_shmat(shmid, 0);
  if(shm != (void*)-1)
  {
    ((int*)shm)[0] = MAGIC_SHM_VALUE;
  }
  caller_params->shmid = shmid;
  caller_params->shm_offset = 0;
  caller_params->shm_size = shm_size;
  
  // Assign the relay/schrodinger page for enclave
  unsigned long mm_arg_size = 0x1000 * 4;
  int mm_arg_id = PLenclave_schrodinger_get(mm_arg_size);
  void* mm_arg = PLenclave_schrodinger_at(mm_arg_id, 0);
  if(mm_arg != (void*)-1)
  {
    ((int*)mm_arg)[0] = MAGIC_RELAY_PAGE_VALUE;
  }

  char enclave_name[15];
  sprintf(enclave_name, "test-caller");
  strcpy(caller_params->name, enclave_name);

  if(PLenclave_create(caller_enclave, caller_enclaveFile, caller_params) < 0 )
  {
    printf("host: failed to create caller_enclave\n");
    goto out;
  }

  PLenclave_attest(caller_enclave, 1234);
  printHex((unsigned char*)(caller_enclave->attest_param.report.enclave.signature), 64);

  if(mm_arg_id > 0 && mm_arg)
      PLenclave_set_mem_arg(caller_enclave, mm_arg_id, 0, mm_arg_size);

  PLenclave_run(caller_enclave);

  PLenclave_shmdt(shmid, shm);
  PLenclave_shmctl(shmid);
  PLenclave_schrodinger_dt(mm_arg_id, mm_arg);
  PLenclave_schrodinger_ctl(mm_arg_id);

out:
  if(server_enclaveFile)
  {
    elf_args_destroy(server_enclaveFile);
    free(server_enclaveFile);
  }
  if(server_enclave)
  {
    PLenclave_destroy(server_enclave);
    free(server_enclave);
  }
  if(server_params)
  {
    free(server_params);
  }
  if(server1_enclaveFile)
  {
    elf_args_destroy(server1_enclaveFile);
    free(server1_enclaveFile);
  }
  if(server1_enclave)
  {
    PLenclave_destroy(server1_enclave);
    free(server1_enclave);
  }
  if(server1_params)
  {
    free(server1_params);
  }
  if(caller_enclaveFile)
  {
    elf_args_destroy(caller_enclaveFile);
    free(caller_enclaveFile);
  }
  if(caller_enclave)
  {
    free(caller_enclave);
  }
  if(caller_params)
  {
    free(caller_params);
  }

  return 0;
}
