#include "eapp.h"
#include <stdlib.h>
#include <stdio.h>
#include "print.h"
int mem(unsigned long * args)
{
  eapp_print("begin test malloc\n");
  char *ptr, *ptr2;
  int i;
  ptr = (char*)malloc(0x100);
  ptr2 = (char*)calloc(64*64*3*10,sizeof(float));
  for(i = 0; i < 10; i++)
  {
    ptr[i] = 1;
  }
  for(i = 0; i < 10; i++)
  {
    ptr2[i] = 1;
  }

  free(ptr2);
  ptr2 = (char*)malloc(0x100);
  free(ptr);
  free(ptr2);
  eapp_print("end test malloc\n");

  eapp_print("begin test mmap\n");
  unsigned long sum = 0;
  unsigned long size = 20*1024*1024;
  unsigned long *nums = eapp_mmap(NULL, size);

  for(i = 0; i < (size/sizeof(unsigned long)); ++i)
  {
    nums[i] = 1;
  }
  for(i = 0; i < (size/sizeof(unsigned long)); ++i)
  {
    sum += nums[i];
  }
  eapp_unmap((void*)nums, size);
  eapp_print("end test mmap:%d\n", sum);

  eapp_print("begin test sbrk\n");
  nums = sbrk(0);
  unsigned long *num = nums;
  eapp_print("ret of sbrk(0):0x%lx\n", nums);
  nums = sbrk(0 - 0x1000);
  eapp_print("ret of sbrk(-4096):0x%lx\n", nums);
  nums = sbrk(0x4000);
  eapp_print("ret of sbrk(4*4096):0x%lx\n", nums);
  nums = sbrk(0x1000);
  eapp_print("ret of sbrk(1*4096):0x%lx\n", nums);
  sum = 0;
  for(unsigned long *num0=num; num0!=nums; ++num0)
  {
    *num0 = sizeof(unsigned long);
  }
  for(unsigned long *num0=num; num0!=nums; ++num0)
  {
    sum += *num0;
  }
  nums = sbrk(0 - 10*0x1000);
  eapp_print("ret of sbrk(-10*4096):0x%lx\n", nums); 
  eapp_print("end test sbrk\n");

  EAPP_RETURN(sum);
  EAPP_RETURN((unsigned long)10);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  mem(args);
}
