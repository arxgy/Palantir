#include "ocall.h"
#include "eapp.h"

unsigned long get_enclave_id()
{
  unsigned long retval = 0;
  retval = EAPP_GET_ENCLAVE_ID();
  return retval;
}