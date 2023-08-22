/**
 * This program is a Normal Enclave demo in Memory Inspection case study,
 * which sequentially simulates a buffer-overflow and a ROP attack.
 *  by Anonymous Author @ May 24, 2023.
*/
#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>

#define MEM_DUMP_SIZE  512
#define BUF_SZ         12
int sim_input(char *buf)
{
  char *input = "HELLOWORLD?!?DDHDS";
  strcpy(buf, input);
  return 0;
}

int hello(unsigned long * args)
{ 
  ocall_request_inspect_t inspect_req;
  ocall_request_t req;
  req.request = NE_REQUEST_INSPECT;
  req.inspect_request = (unsigned long)(&inspect_req);
  req.share_page_request = NULL;
  eapp_print("[ne] request_arg [%p], inspect_arg [%p].\n",
              (void *)(&req), (void *)(&inspect_req));
              
  unsigned long selector = 0;
  char buffer[BUF_SZ];
  inspect_req.inspect_ptr = (unsigned long)(&selector);
  inspect_req.inspect_size = (unsigned long)(sizeof(unsigned long));
  eapp_print("[ne] selector address: [%lx]\n", (unsigned long)(&selector));
  eapp_pause_enclave((unsigned long)(&req));
  sim_input(buffer);
  eapp_pause_enclave((unsigned long)(&req));
  if (!selector)
  {
    eapp_print("[ne] hello world!\n");
    EAPP_RETURN(0);
  }
  else 
  {
    eapp_print("[ne] Oops.. Unexpected selector Value!\n");
    EAPP_RETURN(1);
  }
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
