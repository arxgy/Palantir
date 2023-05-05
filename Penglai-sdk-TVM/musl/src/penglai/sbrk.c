#include "ocall.h"
#include "eapp.h"

extern unsigned long EAPP_OCALL(unsigned long ocall_func_id, long size);
void* sbrk(long size)
{
  void* retval = 0;
  retval = (void*)EAPP_OCALL(OCALL_SBRK, size);
  return retval;
}
