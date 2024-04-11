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
#define MEGABYTE_SZ 1 << 20
#define SIZE_ORDER 6

unsigned long global_array [1024];    // .bss
unsigned long global_zero = 0;        // .sbss
char *global_str = "global_str_test"; // .sdata
unsigned long global_ul = 2048;       // .sdata
unsigned long global_ul_a = 20488;    // .sdata
unsigned long global_ul_b = 204888;   // .sdata
unsigned long global_ul_c = 2048889;  // .sdata

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

unsigned long begin_cycle;
unsigned long end_cycle;

int execute(unsigned long * args)
{
	eapp_print("[BREAKDOWN] TOTAL cost (w/ alloc): %lx (cycle)\n", get_cycle() - begin_cycle);
  // register void *sp asm ("sp");
  // eapp_print("[Payload] %p", sp);

  int i = 0, j = 0;
  ocall_request_t req;
  req.request = NE_REQUEST_REWIND;
  req.inspect_request = NULL;
  req.share_page_request = NULL;

  for (j = 0 ; j < (1 << SIZE_ORDER) ; j++ )
  {
    void *p = malloc(MEGABYTE_SZ);
    memset(p, 0, MEGABYTE_SZ);
  }
	// eapp_print("[BREAKDOWN] malloc cost: %lx (cycle)\n", get_cycle() - end_cycle);
	eapp_print("[BREAKDOWN] COMMUNICATION (PAUSE start): %lx\n", get_cycle());
  begin_cycle = get_cycle();
  eapp_pause_enclave((unsigned long)(&req));

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
