#ifndef _PSA_ENCRYPTED_OBJECT
#define _PSA_ENCRYPTED_OBJECT
#include "eapp.h"
#include "print.h"
#include "psa/protected_storage.h"
#include "psa/storage_common.h"
#include <string.h>
#include <stdlib.h>
#include "psa_server.h"
#include "wolfcrypt/aes.h"
#include <fcntl.h>
#include "fscallargs.h"
#include <sys/stat.h>
#include "sst_utils.h"
#include "sst_object_defs.h"
psa_status_t sst_encrypted_object_read(uint32_t fid, struct sst_object_t *obj, uint32_t idx);
psa_status_t sst_encrypted_object_write(uint32_t fid, struct sst_object_t *obj, uint32_t idx);
void sst_crypto_get_iv(union sst_crypto_t *crypto);
#endif