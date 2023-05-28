#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>

#define SIZE 130000000

char dummy[SIZE] = {'a'};

int hello(unsigned long * args) {
    dummy[SIZE-1] = '\n';
    if(dummy[0] == 'a')
    {
        eapp_print("Hello, bloated world");
    }
    EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}
