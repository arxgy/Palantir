#include "psa_object_server.h"
#include "sst_object_defs.h"
#include "psa_object_table.h"
#include "psa_encrypted_object.h"
#include "psa_server.h"
#include "sst_utils.h"
#define SST_INVALID_FID  0
#define SST_DEFAULT_EMPTY_BUFF_VAL 0
static struct sst_object_t g_sst_object;
static struct sst_obj_table_info_t g_obj_tbl_info;

psa_status_t sst_system_prepare(void)
{
    psa_status_t err;

    /* Reuse the allocated g_sst_object.data to store a temporary object table
     * data to be validate inside the function.
     * The stored date will be cleaned up when the g_sst_object.data will
     * be used for the first time in the object system.
     */
    err = sst_object_table_init(g_sst_object.data);

    g_obj_tbl_info.tag = g_sst_object.header.crypto.ref.tag;

    return err;
}

void sst_init_empty_object( psa_storage_create_flags_t create_flags,
                            uint32_t size,
                            struct sst_object_t *obj)
{
    /* Set all object data to 0 */
    (void)memset(obj, SST_DEFAULT_EMPTY_BUFF_VAL, SST_MAX_OBJECT_SIZE);

    /* Set object header based on input parameters */
    obj->header.info.max_size = size;
    obj->header.info.create_flags = create_flags;
}

psa_status_t sst_object_create(psa_storage_uid_t uid, int32_t client_id,
                               psa_storage_create_flags_t create_flags,
                               uint32_t size)
{
    psa_status_t err;
    uint32_t old_fid = SST_INVALID_FID;
    uint32_t fid_am_reserved = 1;

    uint32_t wrt_size;

    /* Retrieve the object information from the object table if the object
     * exists.
     */
    // eapp_print("sst_object_create: uid is %d client is %d \n", uid, client_id);
    uint32_t old_id, is_existed = 0;
    err = sst_object_table_get_obj_tbl_info(uid, client_id, &g_obj_tbl_info, &old_id);
    if (err == PSA_SUCCESS) {
        /* Read the object */
        is_existed = 1;
        err = sst_encrypted_object_read(g_obj_tbl_info.fid, &g_sst_object, old_id);
        close(g_obj_tbl_info.fid);
        if (err != PSA_SUCCESS) {
            eapp_print("sst_object_create: sst_encrypted_object_read is failed \n");
            goto clear_data_and_return;
        }
        //Finish the sst encrypted object object
        /* If the object exists and has the write once flag set, then it cannot
         * be modified.
         */
        if (g_sst_object.header.info.create_flags
            & PSA_STORAGE_FLAG_WRITE_ONCE) {
            err = PSA_ERROR_NOT_PERMITTED;
            eapp_print("sst_object_create: write a write once file twice \n");
            goto clear_data_and_return;
        }

        /* Update the create flags and max object size */
        g_sst_object.header.info.create_flags = create_flags;
        g_sst_object.header.info.max_size = size;

        /* Save old file ID */
        old_fid = g_obj_tbl_info.fid;
    } else if (err == PSA_ERROR_DOES_NOT_EXIST) {
        /* If the object does not exist, then initialize it based on the input
         * arguments and empty content. Requests 2 FIDs to prevent exhaustion.
         */
        fid_am_reserved = 2;
        sst_init_empty_object(create_flags, size, &g_sst_object);
        eapp_print("sst_object_create: sst_init_empty_object is not existed\n");
    } else {
        close(g_obj_tbl_info.fid);
        eapp_print("sst_object_create: sst_object_table_get_obj_tbl_info inccurs an unexpected error \n");
        goto clear_data_and_return;
    }
    /* Updata the user provided data into the g_sst_object.data */
    err = sst_req_mngr_read_asset_data(g_sst_object.data, size);
    if (err != PSA_SUCCESS) {
        eapp_print("sst_object_create: sst_req_mngr_read_asset_data is failed\n");
        goto clear_data_and_return;
    }
    /* Update the current object size */
    g_sst_object.header.info.current_size = size;
    /* Get new file ID */
    uint32_t tmp_id;
    err = sst_object_table_get_free_fid(fid_am_reserved,
                                        &g_obj_tbl_info.fid, &tmp_id);
    if (err != PSA_SUCCESS) {
        eapp_print("sst_object_create: sst_object_table_get_free_fid is failed \n");
        goto clear_data_and_return;
    }
    // eapp_print("sst_object_create: fid is %d and data is %s\n", g_obj_tbl_info.fid, g_sst_object.data);
    /* Encrypt the data and write into the persistency storage. (create a new object into the persistent storage) */
    err = sst_encrypted_object_write(g_obj_tbl_info.fid, &g_sst_object, tmp_id);
    if (err != PSA_SUCCESS) {
        eapp_print("sst_object_create: sst_encrypted_object_write is failed \n");
        goto clear_data_and_return;
    }
    close(g_obj_tbl_info.fid);
    /* Update the table with the new internal ID and version for the object, and
     * store it in the persistent area.
     */
    err = sst_object_table_set_obj_tbl_info(uid, client_id, &g_obj_tbl_info, tmp_id);
    if (err != PSA_SUCCESS)
    {
        /* remove the new object, as obj_table is not persistenct */
        sst_object_delete_from_persistent_storage(tmp_id);
        eapp_print("sst_object_create: sst_object_table_set_obj_tbl_info is failed, unlink the object file \n");
        goto clear_data_and_return;
    }
    /* Remove the stale object from the persistent storage */
    if (is_existed)
    {    
        sst_object_delete_from_persistent_storage(old_id);
    }
    
    //don't forget to close two fid
clear_data_and_return:
    /* Remove data stored in the object before leaving the function */
    (void)memset(&g_sst_object, SST_DEFAULT_EMPTY_BUFF_VAL,
                     SST_MAX_OBJECT_SIZE);

    // return err;
    // eapp_print("sst_object_create: finish! \n");
    return err;
}

psa_status_t sst_object_read(psa_storage_uid_t uid, int32_t client_id,
                             uint32_t offset, uint32_t size,
                             size_t* p_data_length)
{
    psa_status_t err;
    uint32_t old_id;
    /* Retrieve the object information from the object table if the object
     * exists.
     */
    err = sst_object_table_get_obj_tbl_info(uid, client_id, &g_obj_tbl_info, &old_id);
    if (err != PSA_SUCCESS) {
        eapp_print("sst_object_read: sst_object_table_get_obj_tbl_info is failed\n");
        return err;
    }
    // eapp_print("sst_object_read: idx is %d\n", old_id);
    /* Read object */
    err = sst_encrypted_object_read(g_obj_tbl_info.fid, &g_sst_object, old_id);
    close(g_obj_tbl_info.fid);
    if (err != PSA_SUCCESS) {
        eapp_print("sst_object_read: sst_encrypted_object_read is failed\n");
        goto clear_data_and_return;
    }

    /* Boundary check the incoming request */
    if (offset > g_sst_object.header.info.current_size) {
        eapp_print("sst_object_read: offset is large than the current size\n");
        err = PSA_ERROR_INVALID_ARGUMENT;
        goto clear_data_and_return;
    }

    size = MIN(size, g_sst_object.header.info.current_size - offset);

    /* Copy the decrypted object data to the output buffer */
    sst_req_mngr_write_asset_data(g_sst_object.data + offset, size);
    *p_data_length = size;

clear_data_and_return:
    /* Remove data stored in the object before leaving the function */
    (void)memset(&g_sst_object, SST_DEFAULT_EMPTY_BUFF_VAL,
                     SST_MAX_OBJECT_SIZE);

    return err;
}

psa_status_t sst_object_get_info(psa_storage_uid_t uid, int32_t client_id,
                                 struct psa_storage_info_t *info)
{
    psa_status_t err;

    /* Retrieve the object information from the object table if the object
     * exists.
     */
    uint32_t old_id;
    err = sst_object_table_get_obj_tbl_info(uid, client_id, &g_obj_tbl_info, &old_id);
    if (err != PSA_SUCCESS) {
        return err;
    }
    // eapp_print("sst_object_get_info: idx is %d\n", old_id);
    err = sst_encrypted_object_read(g_obj_tbl_info.fid, &g_sst_object, old_id);
    close(g_obj_tbl_info.fid);
    if (err != PSA_SUCCESS) {
        goto clear_data_and_return;
    }
    // eapp_print("sst_object_get_info: size is %d\n", g_sst_object.header.info.current_size);
    /* Copy SST object info to the PSA PS info struct */
    info->size = g_sst_object.header.info.current_size;
    info->flags = g_sst_object.header.info.create_flags;

clear_data_and_return:
    /* Remove data stored in the object before leaving the function */
    (void)memset(&g_sst_object, SST_DEFAULT_EMPTY_BUFF_VAL,
                     SST_MAX_OBJECT_SIZE);

    return err;
}

psa_status_t sst_object_delete(psa_storage_uid_t uid, int32_t client_id)
{
    psa_status_t err;

    /* Retrieve the object information from the object table if the object
     * exists.
     */
    uint32_t old_id;
    err = sst_object_table_get_obj_tbl_info(uid, client_id, &g_obj_tbl_info, &old_id);
    if (err != PSA_SUCCESS) {
        return err;
    }

    err = sst_encrypted_object_read(g_obj_tbl_info.fid, &g_sst_object, old_id);

    if (err != PSA_SUCCESS) {
        goto clear_data_and_return;
    }

    /* Check that the write once flag is not set */
    if (g_sst_object.header.info.create_flags & PSA_STORAGE_FLAG_WRITE_ONCE) {
        err = PSA_ERROR_NOT_PERMITTED;
        goto clear_data_and_return;
    }

    /* Delete object from the table and stores the table in the persistent
     * area.
     */
    err = sst_object_table_delete_object(uid, client_id);
    if (err != PSA_SUCCESS) {
        goto clear_data_and_return;
    }

    /* Remove old object table and file */
    err = sst_object_delete_from_persistent_storage(old_id);

clear_data_and_return:
    /* Remove data stored in the object before leaving the function */
    (void)memset(&g_sst_object, SST_DEFAULT_EMPTY_BUFF_VAL,
                     SST_MAX_OBJECT_SIZE);

    return err;
}