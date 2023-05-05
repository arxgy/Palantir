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
  unsigned long* args;
  EAPP_RESERVE_REG;
  unsigned long arg0 = args[10];
  void* vaddr = (void*)args[11];
  unsigned long size = args[12];
  eapp_print("server1: begin to run\n");

  unsigned long sum = arg0;
  if(vaddr)
  {
    int* nums = (int*)vaddr;
    for(int i=0; i<size/sizeof(int); ++i)
    {
      sum += nums[i];
      nums[i] += 1;
    }
  }

  char server_name[16];
  strcpy(server_name, "test-server");

  // Get the server enclave report
  eapp_print("get the server enclave report\n");
  struct report_t *server_report = malloc(sizeof(struct report_t));
  get_report("test-server", server_report, 1);
  printHex((unsigned int*)(server_report->enclave.signature), 16);

  unsigned long server_handle = acquire_enclave(server_name);
  struct call_enclave_arg_t call_arg;
  eapp_print("server1: server_handle:0x%lx\n", server_handle);
  if(server_handle == -1UL)
  {
    call_arg.resp_val = -1;
    call_arg.req_vaddr = 0;
    call_arg.resp_vaddr = 0;
    SERVER_RETURN(&call_arg);
  }

  call_arg.req_arg = arg0;
  call_arg.req_vaddr = (unsigned long)vaddr;
  call_arg.req_size = size;
  call_enclave(server_handle, &call_arg);
  eapp_print("server1: read req_vaddr:0x%lx\n", sum);

  if(call_arg.resp_vaddr)
  {
    int *nums = (int*)call_arg.resp_vaddr;
    size = call_arg.resp_size;
    sum = arg0;
    for(int i=0; i<size/sizeof(int); ++i)
    {
      sum += nums[i];
    }
    eapp_print("server1: read resp_vaddr:0x%lx\n", sum);
  }

  call_arg.resp_val = 3;
  eapp_print("server1: exit with retval:0x%lx\n", 3);
  SERVER_RETURN(&call_arg);
}
