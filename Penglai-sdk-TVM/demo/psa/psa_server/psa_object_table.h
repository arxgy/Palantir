#ifndef _PSA_OBJECT_TABLE
#define _PSA_OBJECT_TABLE
#include "eapp.h"
#include "print.h"
#include "psa/protected_storage.h"
#include "psa/storage_common.h"
#include <string.h>
#include <stdlib.h>
#include "psa_server.h"
#include "wolfcrypt/aes.h"

#include <fcntl.h>

enum psa_nv_counter_t {
    PLAT_NV_COUNTER_0 = 0,  /* Used by SST service */
    PLAT_NV_COUNTER_1,      /* Used by SST service */
    PLAT_NV_COUNTER_2,      /* Used by SST service */
    PLAT_NV_COUNTER_3,      /* Used by bootloader */
    PLAT_NV_COUNTER_4,      /* Used by bootloader */
    PLAT_NV_COUNTER_MAX
};


struct sst_obj_table_info_t {
    uint32_t fid;      /*!< File ID in the file system */
    uint8_t *tag;      /*!< Pointer to the MAC value of AEAD object */
    uint32_t version;  /*!< Object version */
};

#include "sst_utils.h"
#include "sst_object_defs.h"
static struct sst_obj_table_ctx_t sst_obj_table_ctx;
psa_status_t sst_object_table_init(uint8_t *obj_data);

psa_status_t sst_object_table_get_obj_tbl_info(psa_storage_uid_t uid,
                                               int32_t client_id,
                                      struct sst_obj_table_info_t *obj_tbl_info, uint32_t* old_id);

psa_status_t sst_object_table_get_free_fid(uint32_t fid_num,
                                           uint32_t *p_fid, uint32_t *tmp_id);

psa_status_t sst_object_table_set_obj_tbl_info(psa_storage_uid_t uid,
                                               int32_t client_id,
                                const struct sst_obj_table_info_t *obj_tbl_info, uint32_t tmp_id);

psa_status_t sst_object_delete_from_persistent_storage(uint32_t idx);

psa_status_t sst_object_table_delete_object(psa_storage_uid_t uid,
                                            int32_t client_id);
#endif