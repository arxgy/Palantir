/**
 * This program is a Normal Enclave demo in Memory Sharing evaluation, 
 * which plays a sharer/sender role in memory sharing and 
 *       sends sharing request to PE.
 *  by Anonymous Author @ May 28, 2023.
*/
#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>
#define LOG_ACQUIRE_PAGE 10

int hello(unsigned long * args)
{
  char *content = (char *)eapp_mmap(NULL, PAGE_SIZE<<LOG_ACQUIRE_PAGE);

  ocall_request_share_t share_req;
  share_req.share_content_ptr = (unsigned long)(content);
  share_req.share_size = PAGE_SIZE<<LOG_ACQUIRE_PAGE;

  ocall_request_t req;
  req.request = NE_REQUEST_SHARE_PAGE;
  req.inspect_request = NULL;
  req.share_page_request = (unsigned long)(&share_req);
  eapp_pause_enclave((unsigned long)(&req));

  /* similuating do other things. */
  unsigned iter;
  iter = 0;
  while (iter < 1 << 30)
  {
    iter++;
  }
  
  eapp_print("[ne] [sharer] hello world!\n");
  EAPP_RETURN(255);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
