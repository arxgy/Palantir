#include "eapp.h"
#include "print.h"
#include <string.h>
#include <stdlib.h>

void printHex(unsigned int *c, int n)
{
	int i;
	for (i = 0; i < n; i++) {
    eapp_print("0x%x\n", c[i]);
	}
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;

  eapp_print("caller begin to run...\n");

  // Get the content in the shared memory
  int *shm = (int *)args[10];
  unsigned shm_size = (unsigned long) args[11];

  // Get the content in the ralay/schrodinger page (zero copy) 
  int *relay_page = (int *)args[13];
  unsigned relay_page_size = (unsigned long) args[14];   

  eapp_print("shm content %d and size %lx\n", *shm, shm_size);

  eapp_print("relay page content %d and size %lx\n", *relay_page, relay_page_size);

  int run_server1 = 1;
  char server_name[16];
  strcpy(server_name, "test-server1");

  unsigned long server_handle = acquire_enclave(server_name);
  if(server_handle == -1UL)
  {
    strcpy(server_name, "test-server");
    server_handle = acquire_enclave(server_name);
    run_server1 = 0;
  }

  eapp_print("get the enclave report\n");

  // Get the server enclave report
  struct report_t *report = malloc(sizeof(struct report_t));
  get_report(NULL, report, 1);
  printHex((unsigned int*)(report->enclave.signature), 16);

  eapp_print("get the server1 enclave report\n");

  // Get the server enclave report
  struct report_t *server_report = malloc(sizeof(struct report_t));
  get_report("test-server1", server_report, 1);
  printHex((unsigned int*)(server_report->enclave.signature), 16);


  if(server_handle == -1UL)
  {
    EAPP_RETURN(-1UL);
  }

  unsigned long arg0 = 0x19960000UL;
  unsigned long size = 4*4096;
  int *nums = eapp_mmap(NULL, size);
  // int *nums = malloc(size);
  for(int i=0; i<size/sizeof(int); ++i)
  {
    nums[i] = 1;
  }

  struct call_enclave_arg_t call_arg;
  call_arg.req_arg = arg0;
  call_arg.req_vaddr = (unsigned long)nums;
  call_arg.req_size = size;
  call_enclave(server_handle, &call_arg);

  if(call_arg.req_vaddr)
  {
    unsigned long sum = 0;
    //nums = (int*)call_arg.req_vaddr;
    for(int i=0; i<size/sizeof(int); ++i)
    {
      sum += nums[i];
    }
    eapp_print("caller: read req_vaddr after calling server:0x%lx\n", sum);
  }

  if(call_arg.resp_vaddr)
  {
    unsigned long sum = 0;
    nums = (int*)call_arg.resp_vaddr;
    for(int i=0; i<call_arg.resp_size/sizeof(int); ++i)
    {
      sum += nums[i];
    }
    eapp_print("caller: read resp_vaddr after calling server:0x%lx\n", sum);
  }

  if(run_server1)
    eapp_print("caller: get server1 retval:0x%lx\n", call_arg.resp_val);
  else
    eapp_print("caller: get server retval:0x%lx\n", call_arg.resp_val);
  EAPP_RETURN(0);
}
