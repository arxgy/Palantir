#include "ocall.h"
#include "eapp.h"
#include "print.h"
void* eapp_mmap(void* vaddr, unsigned long size)
{
  void* retval = 0;
  retval = (void*)EAPP_MMAP(OCALL_MMAP, vaddr, size);
  while (retval == 0)
  {
    eapp_print("[WARNING] lib: eapp_mmap is failed\n");
    retval = (void*)EAPP_MMAP(OCALL_MMAP, vaddr, size);
  }
  return retval;
}

int eapp_unmap(void* vaddr, unsigned long size)
{
  int retval = 0;
  retval = EAPP_UNMAP(OCALL_UNMAP, vaddr, size);
  return retval;
}

int eapp_return_relay_page()
{
  int retval = 0;
  retval = EAPP_RETURN_RELAY_PAGE(OCALL_RETURN_RELAY_PAGE);
  return retval;
}
