/**
 * This program is a Normal Enclave demo in Interface-level Evaluation.
 * SIZE is defined to expand our elf file size to maximal 128MB for create test.
 *  by Ganxiang Yang @ May 28, 2023.
*/
#include "eapp.h"
#include "privil.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>

#define SIZE 16000000

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
