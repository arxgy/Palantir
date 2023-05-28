/**
 * This program is a Normal Enclave demo in Memory Inspection evaluation
 * which allocate a 1MB pages and return start address to PE.
 *  by Ganxiang Yang @ May 24, 2023.
*/
#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>

#define MEM_DUMP_SIZE  512
#define BUF_SZ         12

int hello(unsigned long * args)
{ 
  char *buffer = (char *)eapp_mmap(NULL, 1<<26);

  ocall_request_inspect_t inspect_req;
  ocall_request_t req;
  req.request = NE_REQUEST_INSPECT;
  req.inspect_request = (unsigned long)(&inspect_req);
  req.share_page_request = NULL;
  inspect_req.inspect_ptr = (unsigned long)(buffer);
  eapp_pause_enclave((unsigned long)(&req));
  eapp_print("[ne] [eval-inspectee] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
