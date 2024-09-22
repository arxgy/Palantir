/**
 * This program is a Privileged Enclave demo in Reusable Enclave case study,
 * which is supported to do nested attestation on a nested PE (reset module) and a NE (serverless payload w/o WASM runtime).
 * 
 *  by Anonymous Author @ Apr 4, 2024.
*/
#include "eapp.h"
#include "print.h"
#include "privil.h"
// #include "hdwallet.h"
#include "bip32_bip39.h"
#include "aes_coin/aes_coin.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define ENTRY_POINT 0x1000

int execute(unsigned long * args)
{
  
  eapp_print("[pe] [case-root] N_COLS: %d\n", N_COLS);
  eapp_print("[pe] [case-root] FROMHEX_MAXLEN: %d\n", FROMHEX_MAXLEN);
  EAPP_RETURN(0);

}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
}
