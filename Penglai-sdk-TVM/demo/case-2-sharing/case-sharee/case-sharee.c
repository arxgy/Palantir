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
  eapp_print("[ne] [sharee] hello world!\n");
  EAPP_RETURN(127);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
