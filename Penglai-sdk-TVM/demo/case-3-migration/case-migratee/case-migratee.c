/**
 * This program is a Normal Enclave demo in Live Enclave Migration case study,
 * which will 
 *  1. be stopped and destroyed by a PE, generate dumpfile which stores memory states.
 *  2. be resumed by another PE and run again.
 * \details During migration, we will ensure the Integrity of data in mmap/heap/stack/code regions. 
 *          But since in this case we only migrate single Normal Enclave (migratee), 
 *          we cannot ensure some specific sharing features given by Penglai, such as Relay Page and shm.
 *  by Anonymous Author @ May 25, 2023.
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
  void *content = NULL;

  // content = eapp_mmap(NULL, PAGE_SIZE+4095);
  // eapp_print("[ne] eapp_mmap address: [%p]\n", content);
  
  int i = 0;
  for (i = 0; i < 5 ; i++)
  {
    void *p = malloc(sizeof(unsigned long)*128);
    eapp_print("[ne] malloc address: [%p]\n", p);
    eapp_pause_enclave((unsigned long)(&req));
  }
  content = eapp_mmap(NULL, PAGE_SIZE);
  eapp_print("[ne] eapp_mmap address: [%p]\n", content);
  eapp_pause_enclave((unsigned long)(&req));

  int iter = 0;
  memset((void *)content, 0, PAGE_SIZE);

  char *c_content = (char *)content;
  for (iter = 0 ; iter < PAGE_SIZE ; iter++)
  {
    switch (iter % 4)
    {
    case 0:
      c_content[iter] = '0';
      break;
    case 1:
      c_content[iter] = '1';
      break;
    case 2:
      c_content[iter] = '2';
      break;
    case 3:
      c_content[iter] = '3';
      break;
    default:
      break;
    }
  }

  while (iter < 1 << 22) 
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
