#ifndef _PSA_OBJECT_SERVER
#define _PSA_OBJECT_SERVER
#include "eapp.h"
#include "print.h"
#include "psa/protected_storage.h"
#include "psa/storage_common.h"
#include <string.h>
#include <stdlib.h>
#include "psa_server.h"
#include "wolfcrypt/aes.h"
psa_status_t sst_system_prepare(void);

psa_status_t sst_object_create(psa_storage_uid_t uid, int32_t client_id,
                               psa_storage_create_flags_t create_flags,
                               uint32_t size);

psa_status_t sst_object_read(psa_storage_uid_t uid, int32_t client_id,
                             uint32_t offset, uint32_t size,
                             size_t* p_data_length);

psa_status_t sst_object_get_info(psa_storage_uid_t uid, int32_t client_id,
                                 struct psa_storage_info_t *info);

psa_status_t sst_object_delete(psa_storage_uid_t uid, int32_t client_id);
#endif