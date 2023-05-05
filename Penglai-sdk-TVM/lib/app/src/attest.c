#include "ocall.h"
#include "eapp.h"
#include "attest.h"

int get_report(char* name, struct report_t *report, unsigned long nonce)
{
  int ret = 0;
  ret = EAPP_GET_REPORT(name, report, nonce);
  return ret;
}

int get_key(int ket_type, char *key, int key_size)
{
  int ret = 0;
  ret = EAPP_GET_KEY(ket_type, key, key_size);
  return ret;
}