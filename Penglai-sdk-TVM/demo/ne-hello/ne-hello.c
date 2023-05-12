#include "eapp.h"
#include "print.h"
#include <stdlib.h>

int hello(unsigned long * args)
{
  printf("hello world!\n");
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
