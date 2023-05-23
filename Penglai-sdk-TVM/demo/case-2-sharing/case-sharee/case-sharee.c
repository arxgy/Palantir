/**
 * This program is a Normal Enclave demo in Memory Sharing case study, 
 * which plays a sharee/recver role in memory sharing, 
 *       sends acquiring shared-page request to PE,
 *       and receive the corresponding sharer page.
 *  by Ganxiang Yang @ May 22, 2023.
*/
#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>

#define MAGIC_PEER_EID 4097
#define MAGIC_PAGE_ID  1
int hello(unsigned long * args)
{
  char content[PAGE_SIZE];
  memset((void *)content, 0, PAGE_SIZE);
  
  ocall_request_share_t share_req;
  share_req.eid = MAGIC_PEER_EID;
  share_req.share_id = MAGIC_PAGE_ID;
  share_req.share_content_ptr = (unsigned long)(content);
  share_req.share_size = PAGE_SIZE;

  ocall_request_t req;
  req.request = NE_REQUEST_ACQUIRE_PAGE;
  req.inspect_request = NULL;
  req.share_page_request = (unsigned long)(&share_req);
  eapp_print("[ne] [sharee] dest_ptr [%lx]\n", (unsigned long)(content));

  int iter = 0;
  while (iter < 1  << 20)
  {
    iter++;
  }
  
  eapp_pause_enclave((unsigned long)(&req));
  eapp_print("%s", content);
  eapp_print("[ne] [sharee] hello world!\n");
  EAPP_RETURN(127);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
