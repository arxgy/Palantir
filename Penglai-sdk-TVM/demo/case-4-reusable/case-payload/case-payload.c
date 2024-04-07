/**
 * This program is a Privileged Enclave demo in Reusable Enclave case study,
 * which is supported to do nested attestation on a nested PE (reset module) and a NE (serverless payload w/o WASM runtime).
 * 
 *  by Anonymous Author @ Apr 4, 2024.
*/
#include "eapp.h"
#include "print.h"
#include "privil.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define ENTRY_POINT 0x1000

unsigned long global_array [1024];    // .bss
unsigned long global_zero = 0;        // .sbss
char *global_str = "global_str_test"; // .sdata
unsigned long global_ul = 2048;       // .sdata
unsigned long global_ul_a = 20488;    // .sdata
unsigned long global_ul_b = 204888;   // .sdata
unsigned long global_ul_c = 2048889;  // .sdata

typedef unsigned char u8;
typedef unsigned int u32;

int execute(unsigned long * args)
{
  register void *sp asm ("sp");
  eapp_print("[Payload] %p", sp);
  int i = 0;
  ocall_request_t req;
  req.request = NE_REQUEST_REWIND;
  req.inspect_request = NULL;
  req.share_page_request = NULL;

  for (i = 0; i < 8 ; i++)
  {
    unsigned long x = global_array[523];
    eapp_print("[ne] global_array[523]: [%x]\n", x);

    void *p = malloc(sizeof(unsigned long)*128);
    global_ul++;
    global_array[523] = 523;
    eapp_print("[ne] malloc address: [%p]\n", p);
    eapp_print("[ne] global_ul: [%x]\n", global_ul);
    eapp_pause_enclave((unsigned long)(&req));
  }

  for (i = 0 ; i < 1<<22 ; i++)
  {
    /* do something */
  }
  EAPP_RETURN(0);

}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
}
