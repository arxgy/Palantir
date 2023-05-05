#include "ocall.h"
#include "eapp.h"

unsigned long asyn_enclave_call(char* name, struct call_enclave_arg_t *arg)
{
  unsigned long retval = 0;
  retval = EAPP_ASYN_ENCLAVE_CALL(name, arg);
  return retval;
}

unsigned long split_mem_region(unsigned long mem_addr, unsigned long mem_size, unsigned long split_addr)
{
  unsigned long retval = 0;
  retval = EAPP_SPLIT_MEM_REGION(mem_addr, mem_size, split_addr);
  return retval;
}
