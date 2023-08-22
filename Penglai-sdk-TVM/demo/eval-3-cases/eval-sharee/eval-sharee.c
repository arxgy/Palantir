/**
 * This program is a Normal Enclave demo in Memory Sharing evaluation, 
 * which plays a sharee/recver role in memory sharing, 
 *       sends acquiring shared-page request to PE,
 *       and receive the corresponding sharer page.
 *  by Anonymous Author @ May 28, 2023.
*/
#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>

#define MAGIC_PEER_EID 4097
#define MAGIC_PAGE_ID  1
#define LOG_ACQUIRE_PAGE 10

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

int hello(unsigned long * args)
{ 
  unsigned long total_cycle, begin_cycle, end_cycle;
  char *content = (char *)eapp_mmap(NULL, PAGE_SIZE);
  // char content[PAGE_SIZE];
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

  /* simulate do other chore job. */
  int iter = 0;
  while (iter < 1  << 20)
  {
    iter++;
  }
  unsigned long page_num = 1 << LOG_ACQUIRE_PAGE;
  for (iter = 0 ; iter < page_num ; iter++)
  {
    begin_cycle = get_cycle();
    eapp_pause_enclave((unsigned long)(&req));
    end_cycle = get_cycle();
    total_cycle += (end_cycle-begin_cycle);
  }
  eapp_print("[ne] [eval-sharee] total cycle cost: [%lx]\n", total_cycle);
  eapp_print("[ne] [eval-sharee] hello world!\n");
  EAPP_RETURN(127);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
