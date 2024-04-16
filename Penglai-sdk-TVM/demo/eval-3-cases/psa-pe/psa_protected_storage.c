#include "psa_protected_storage.h"
#include "psa_object_server.h"
#define PSA_SST_INVALID_UID 0

psa_status_t psa_sst_set(int32_t client_id,
                         psa_storage_uid_t uid,
                         uint32_t data_length,
                         psa_storage_create_flags_t create_flags)
{
    /* Check that the UID is valid */
    if (uid == PSA_SST_INVALID_UID) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check that the create_flags does not contain any unsupported flags */
    if (create_flags & ~(PSA_STORAGE_FLAG_WRITE_ONCE |
                         PSA_STORAGE_FLAG_NO_CONFIDENTIALITY |
                         PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return sst_object_create(uid, client_id, create_flags, data_length);
}

psa_status_t psa_sst_get(int32_t client_id,
                         psa_storage_uid_t uid,
                         uint32_t data_offset,
                         uint32_t data_size,
                         size_t *p_data_length)
{
    /* Check that the UID is valid */
    if (uid == PSA_SST_INVALID_UID) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Read the object data from the object system */
    return sst_object_read(uid, client_id, data_offset, data_size,
                           p_data_length);
}

psa_status_t psa_sst_get_info(int32_t client_id, psa_storage_uid_t uid,
                              struct psa_storage_info_t *p_info)
{
    /* Check that the UID is valid */
    if (uid == PSA_SST_INVALID_UID) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    eapp_print("psa_sst_get_info: here \n");
    // return PSA_SUCCESS;
    /* Get the info struct data from the object system */
    return sst_object_get_info(uid, client_id, p_info);
}

psa_status_t psa_sst_remove(int32_t client_id, psa_storage_uid_t uid)
{
    psa_status_t err;

    /* Check that the UID is valid */
    if (uid == PSA_SST_INVALID_UID) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Delete the object from the object system */
    err = sst_object_delete(uid, client_id);

    /* PSA_ERROR_INVALID_SIGNATURE is not supported by psa_ps_remove
     * specification. So, this function returns TFM_SST_ERR_OPERATION_FAILED
     * instead.
     */
    if (err == PSA_ERROR_INVALID_SIGNATURE) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return err;
}

uint32_t psa_sst_get_support(void)
{
    /*
     * This function returns a bitmask with flags set for all of the optional
     * features supported by the SST service implementation.
     *
     * SST service does not support the optional extended PSA PS API yet.
     */

    return 0;
}