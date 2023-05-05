#include "eapp.h"
#include "print.h"
#include <stdlib.h>

int test_relay_page(unsigned long * args)
{
  int *relay_page = (int*)args[13];
  eapp_print("relay_page 1 %x\n", *relay_page);
  eapp_print("EAPP: Now start to call relay page ocall from enclave inside\n");
  eapp_return_relay_page();
  eapp_print("EAPP: ocall over\n");
  eapp_print("relay_page 2 %x\n", *relay_page);
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  test_relay_page(args);
}