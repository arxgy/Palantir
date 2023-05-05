#include "eapp.h"
#include "print.h"
#include "psa/protected_storage.h"
#include "psa/storage_common.h"
#include <string.h>
#include <stdlib.h>

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;

  eapp_print("psa client begin to run\n");
  psa_status_t status;
  const psa_storage_uid_t uid = 1;
  const psa_storage_create_flags_t flags = PSA_STORAGE_FLAG_NONE;
  char* write_data = "aaa";
  uint32_t data_len = sizeof("aaa");
  uint32_t offset = 0;
  uint32_t read_len = sizeof("aaa");
  //FIXME: can not write the memory which is pre-allocated on the stack
  char *read_data; 
  uint32_t read_data_len = 0;

  /* Set with no data and no flags and a valid UID */
  status = psa_ps_set(uid, data_len, write_data, flags);
  if (status != PSA_SUCCESS) {
    eapp_print("psa_client: Set should not fail with valid UID\n");
  }
  read_data = malloc(read_len);
  status = psa_ps_get(uid, offset, read_len, read_data,
                      &read_data_len);
  if (status != PSA_SUCCESS) {
    eapp_print("psa_client: Get should not fail\n");
  }

  eapp_print("psa client: read data is %s", read_data);

  struct psa_storage_info_t info = {0};

    /* Get info for write once UID */
  status = psa_ps_get_info(uid, &info);
  eapp_print("psa client: psa_ps_get_info: is finish size is %d\n", info.size);
  status = psa_ps_remove(uid);
  if (status != PSA_SUCCESS) {
    eapp_print("Remove should not fail with valid UID\n");
    return;
  }
  EAPP_RETURN(0);
}
