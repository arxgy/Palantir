#ifndef  _PSA_PROTECTED_STORAGE
#define _PSA_PROTECTED_STORAGE
#include "eapp.h"
#include "print.h"
#include "psa/protected_storage.h"
#include "psa/storage_common.h"
#include <string.h>
#include <stdlib.h>
#include "psa_server.h"
#include "wolfcrypt/aes.h"
psa_status_t psa_sst_set(int32_t client_id,
                         psa_storage_uid_t uid,
                         uint32_t data_length,
                         psa_storage_create_flags_t create_flags);

psa_status_t psa_sst_get(int32_t client_id,
                         psa_storage_uid_t uid,
                         uint32_t data_offset,
                         uint32_t data_size,
                         size_t *p_data_length);
                         
psa_status_t psa_sst_get_info(int32_t client_id, psa_storage_uid_t uid,
                              struct psa_storage_info_t *p_info);

psa_status_t psa_sst_remove(int32_t client_id, psa_storage_uid_t uid);    

uint32_t psa_sst_get_support(void);
#endif