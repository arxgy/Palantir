/**
 * This program is a Normal Enclave demo in Memory Sharing case study, 
 * which plays a sharer/sender role in memory sharing and 
 *       sends sharing request to PE.
 *  by Ganxiang Yang @ May 22, 2023.
*/
#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>

int hello(unsigned long * args)
{
  char content[PAGE_SIZE];
  memset((void *)content, 0, PAGE_SIZE);
  int iter = 0;
  for (iter = 0 ; iter < PAGE_SIZE ; iter++)
  {
    switch (iter % 4)
    {
    case 0:
      content[iter] = '0';
      break;
    case 1:
      content[iter] = '1';
      break;
    case 2:
      content[iter] = '2';
      break;
    case 3:
      content[iter] = '3';
      break;
    default:
      break;
    }
  }
  content[PAGE_SIZE-1] = '\0';
  ocall_request_share_t share_req;
  share_req.share_content_ptr = (unsigned long)(content);
  share_req.share_size = PAGE_SIZE;

  ocall_request_t req;
  req.request = NE_REQUEST_SHARE_PAGE;
  req.inspect_request = NULL;
  req.share_page_request = (unsigned long)(&share_req);
  eapp_print("[ne] [sharer] request_arg [%p], share_arg [%p].\n",
              (void *)(&req), (void *)(&share_req));
  eapp_print("[ne] [sharer] share_ptr [%p]\n", (void *)content);
  eapp_pause_enclave((unsigned long)(&req));
  eapp_print("%s", content);
  iter = 0;
  while (iter < 1 << 22)
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
