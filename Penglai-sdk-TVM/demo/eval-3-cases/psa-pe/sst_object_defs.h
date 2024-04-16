/*
 * Copyright (c) 2018-2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __SST_OBJECT_DEFS_H__
#define __SST_OBJECT_DEFS_H__

#include <stdint.h>

#include "psa/protected_storage.h"
#include "sst_utils.h"
#define SST_MAX_OBJECT_DATA_SIZE  1000 
#define SST_NUM_ASSETS 10

#define SST_OBJ_TABLE_IDX_0 0
#define SST_OBJ_TABLE_IDX_1 1

#define PSA_FILE_LEN 15

/* Number of object tables (active and scratch) */
#define SST_NUM_OBJ_TABLES  2

struct sst_obj_table_entry_t {
    uint8_t tag[SST_TAG_LEN_BYTES]; /*!< MAC value of AEAD object */

    psa_storage_uid_t uid;          /*!< Object UID */
    int32_t client_id;              /*!< Client ID */
};

union sst_crypto_t {
    struct {
        uint8_t tag[SST_TAG_LEN_BYTES]; /*!< MAC value of AEAD object */
        uint8_t iv[SST_IV_LEN_BYTES];   /*!< IV value of AEAD object */
    } ref;
};

#define SST_OBJ_TABLE_ENTRIES (SST_NUM_ASSETS + 1)

enum sst_obj_table_state {
    SST_OBJ_TABLE_VALID = 0,   /*!< Table content is valid */
    SST_OBJ_TABLE_INVALID,     /*!< Table content is invalid */
    SST_OBJ_TABLE_NVC_1_VALID, /*!< Table content valid with NVC 1 value */
    SST_OBJ_TABLE_NVC_3_VALID, /*!< Table content valid with NVC 3 value */
};

struct sst_obj_table_init_ctx_t {
    struct sst_obj_table_t *p_table[SST_NUM_OBJ_TABLES]; /*!< Pointers to  object tables */
    enum sst_obj_table_state table_state[SST_NUM_OBJ_TABLES]; /*!< Array to indicate if the object table X is valid */
    uint32_t nvc_1;        /*!< Non-volatile counter value 1 */
    uint32_t nvc_3;        /*!< Non-volatile counter value 3 */
};

struct  sst_obj_table_t {
    union sst_crypto_t crypto;     /*!< Crypto metadata. */

    uint8_t version;               /*!< SST object system version. */

    struct sst_obj_table_entry_t obj_db[SST_OBJ_TABLE_ENTRIES]; /*!< Table's
                                                                *   entries
                                                                */
};

struct sst_obj_table_ctx_t {
    struct sst_obj_table_t obj_table; /*!< Object tables */
    uint8_t active_table;             /*!< Active object table */
    uint8_t scratch_table;            /*!< Scratch object table */
};
/* Current version of system */
#define SST_OBJECT_SYSTEM_VERSION  0x00

#define SST_OBJ_TABLE_SIZE            sizeof(struct sst_obj_table_t)

/* Object table entry size */
#define SST_OBJECTS_TABLE_ENTRY_SIZE  sizeof(struct sst_obj_table_entry_t)

/* Size of the data that is not required to authenticate */
#define SST_NON_AUTH_OBJ_TABLE_SIZE   sizeof(union sst_crypto_t)

/* Start position to store the object table data in the FS object */
#define SST_OBJECT_TABLE_OBJECT_OFFSET 0

/* The associated data is the header minus the crypto data */
#define SST_CRYPTO_ASSOCIATED_DATA(crypto) ((uint8_t *)crypto + \
                                            SST_NON_AUTH_OBJ_TABLE_SIZE)

/* Object table indexes */
#define SST_OBJ_TABLE_IDX_0 0
#define SST_OBJ_TABLE_IDX_1 1

/* Number of object tables (active and scratch) */
#define SST_NUM_OBJ_TABLES  2
// #define SST_TABLE_FS_ID(idx) (idx + 1)
// //FS id used to store the table
// #define SST_OBJECT_FS_ID(idx) ((idx + 1) + 
//                                 SST_TABLE_FS_ID(SST_OBJ_TABLE_IDX_1))

// //FS id used to store the object
// #define SST_OBJECT_FS_ID_TO_IDX(fid) ((fid - 1) - 
//                                       SST_TABLE_FS_ID(SST_OBJ_TABLE_IDX_1))
#define SST_OBJ_TABLE_AUTH_DATA_SIZE (SST_OBJ_TABLE_SIZE - \
                                      SST_NON_AUTH_OBJ_TABLE_SIZE)

struct sst_crypto_assoc_data_t {
    uint8_t  obj_table_data[SST_OBJ_TABLE_AUTH_DATA_SIZE];
    uint32_t nv_counter;
};

#define SST_CRYPTO_ASSOCIATED_DATA_LEN  sizeof(struct sst_crypto_assoc_data_t)

struct sst_object_info_t {
    uint32_t current_size; /*!< Current size of the object content in bytes */
    uint32_t max_size;     /*!< Maximum size of the object content in bytes */
    psa_storage_create_flags_t create_flags; /*!< Object creation flags */
};

struct sst_obj_header_t {
    union sst_crypto_t crypto;     /*!< Crypto metadata */
    struct sst_object_info_t info; /*!< Object information */
};

struct sst_object_t {
    struct sst_obj_header_t header;         /*!< Object header */
    uint8_t data[SST_MAX_OBJECT_DATA_SIZE]; /*!< Object data */
};

#define SST_OBJECT_HEADER_SIZE    sizeof(struct sst_obj_header_t)
#define SST_MAX_OBJECT_SIZE       sizeof(struct sst_object_t)
#define SST_MAX_NUM_OBJECTS (SST_NUM_ASSETS + 3)
#define SST_INVALID_UID 0
#define SST_ENCRYPT_SIZE(plaintext_size) \
    ((plaintext_size) + SST_OBJECT_HEADER_SIZE - sizeof(union sst_crypto_t))
#define SST_MAX_ENCRYPTED_OBJ_SIZE SST_MAX_OBJECT_DATA_SIZE
#define SST_CRYPTO_BUF_LEN (SST_MAX_ENCRYPTED_OBJ_SIZE + SST_TAG_LEN_BYTES)

#endif /* __SST_OBJECT_DEFS_H__ */
