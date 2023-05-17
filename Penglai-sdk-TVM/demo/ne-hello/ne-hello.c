#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>

#define PAGE_SIZE 1 << 12
int hello(unsigned long * args)
{
  // eapp_print("[ne] hello world!\n");
  char content[PAGE_SIZE];
  memset((void *)content, 0, PAGE_SIZE);
  ocall_request_inspect_t inspect_req;
  inspect_req.inspect_ptr = (unsigned long)(content);
  inspect_req.inspect_size = (unsigned long)PAGE_SIZE;
  eapp_pause_enclave(NE_REQUEST_INSPECT, (unsigned long)(&inspect_req));
  EAPP_RETURN(255);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
