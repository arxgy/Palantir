/**
 * This program is a Normal Enclave demo in Live Enclave Migration case study,
 * which will 
 *  1. be stopped and destroyed by a PE, generate dumpfile which stores memory states.
 *  2. be resumed by another PE and run again.
 * \details During migration, we will ensure the Integrity of data in mmap/heap/stack/code regions. 
 *          But since in this case we only migrate single Normal Enclave (migratee), 
 *          we cannot ensure some specific sharing features given by Penglai, such as Relay Page and shm.
 *  by Ganxiang Yang @ May 25, 2023.
*/
#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>

int hello(unsigned long * args)
{ 
  ocall_request_t req;
  req.request = NE_REQUEST_DEBUG_PRINT;
  req.inspect_request = NULL;
  req.share_page_request = NULL;
  eapp_pause_enclave((unsigned long)(&req));
  void *content = eapp_mmap(NULL, PAGE_SIZE+4095);
  eapp_print("[ne] eapp_mmap address: [%p]\n", content);
  
  int i = 0;
  for (i = 0; i < 5 ; i++)
  {
    void *p = malloc(sizeof(unsigned long)*128);
    eapp_print("[ne] malloc address: [%p]\n", p);
    eapp_pause_enclave((unsigned long)(&req));
  }
  content = eapp_mmap(NULL, PAGE_SIZE*3);
  eapp_print("[ne] eapp_mmap address: [%p]\n", content);
  eapp_pause_enclave((unsigned long)(&req));

  int iter = 0;
  while (iter < 1 << 20) 
  { 
    /* wait. */
    iter++;
  }
  
  eapp_print("[ne] [migratee] hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
