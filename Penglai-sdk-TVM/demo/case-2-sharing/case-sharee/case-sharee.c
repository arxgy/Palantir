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

int hello(unsigned long * args)
{
//   // eapp_print("[ne] hello world!\n");
//   char content[PAGE_SIZE];
//   memset((void *)content, 0, PAGE_SIZE);
//   int iter = 0;
//   for (iter = 0 ; iter < PAGE_SIZE ; iter++)
//   {
//     switch (iter % 4)
//     {
//     case 0:
//       content[iter] = '0';
//       break;
//     case 1:
//       content[iter] = '1';
//       break;
//     case 2:
//       content[iter] = '2';
//       break;
//     case 3:
//       content[iter] = '3';
//       break;
//     default:
//       break;
//     }
//   }
//   content[PAGE_SIZE-1] = '\0';
  
//   ocall_request_inspect_t inspect_req;
//   inspect_req.inspect_ptr = (unsigned long)(content);
//   inspect_req.inspect_size = (unsigned long)PAGE_SIZE;

//   ocall_request_t req;
//   req.request = NE_REQUEST_INSPECT;
//   req.inspect_request = (unsigned long)(&inspect_req);
//   req.share_page_request = NULL;
//   eapp_print("[ne] request_arg [%p], inspect_arg [%p].\n",
//               (void *)(&req), (void *)(&inspect_req));
//   eapp_print("[ne] inspect_ptr [%p]\n", (void *)content);
//   eapp_print("%s", content);
//   eapp_pause_enclave((unsigned long)(&req));
//   // eapp_pause_enclave(NE_REQUEST_INSPECT, (unsigned long)(&inspect_req));
//   eapp_print("[ne] inspect_ptr [%p]\n", (void *)content);
  eapp_print("[ne] [sharee] hello world!\n");
  EAPP_RETURN(127);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}