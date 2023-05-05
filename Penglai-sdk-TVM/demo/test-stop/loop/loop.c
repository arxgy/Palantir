#include "eapp.h"
#include "print.h"

int loop(unsigned long * args)
{
  while(1){}
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  loop(args);
}
