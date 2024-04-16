#ifndef _PSA_CRYPTO_INTERFACE
#define _PSA_CRYPTO_INTERFACE

#include "eapp.h"
#include "print.h"
#include "psa/protected_storage.h"
#include "psa/storage_common.h"
#include <string.h>
#include <stdlib.h>
#include "psa_server.h"
#include "wolfcrypt/aes.h"
#include <sys/stat.h>
#include "sst_utils.h"
#include "sst_object_defs.h"
psa_status_t sst_crypto_auth_and_decrypt(const union sst_crypto_t *crypto,
                                         const uint8_t *add,
                                         size_t add_len,
                                         uint8_t *in,
                                         size_t in_len,
                                         uint8_t *out,
                                         size_t out_size,
                                         size_t *out_len,
                                         uint8_t *salt,
                                         size_t salt_len);
psa_status_t sst_crypto_encrypt_and_tag(union sst_crypto_t *crypto,
                                        const uint8_t *add,
                                        size_t add_len,
                                        const uint8_t *in,
                                        size_t in_len,
                                        uint8_t *out,
                                        size_t out_size,
                                        size_t *out_len,
                                        uint8_t *salt,
                                        size_t salt_len);
psa_status_t sst_crypto_generate_auth_tag(union sst_crypto_t *crypto,
                                          const uint8_t *add,
                                          uint32_t add_len,
                                          uint8_t *salt,
                                          size_t salt_len);
psa_status_t sst_crypto_authenticate(const union sst_crypto_t *crypto,
                                     const uint8_t *add,
                                     uint32_t add_len,
                                     uint8_t *salt,
                                     size_t salt_len);
void sst_crypto_get_iv(union sst_crypto_t *crypto);
void sst_crypto_set_iv(const union sst_crypto_t *crypto);
#endif