#include "eapp.h"
#include "print.h"
#include <stdlib.h>

int hello(unsigned long * args)
{
  eapp_print("[ne] hello world!\n");
  EAPP_RETURN(255);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
