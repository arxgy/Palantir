#include "psa_encrypted_object.h"
#include "psa_crypto_interface.h"


/* Buffer to store the maximum encrypted object */
/* FIXME: Do partial encrypt/decrypt to reduce the size of internal buffer */
static uint8_t sst_crypto_buf[SST_CRYPTO_BUF_LEN];

static psa_status_t sst_object_auth_encrypt(uint32_t fid,
                                            uint32_t cur_size,
                                            struct sst_object_t *obj,
                                            uint32_t idx)
{
    psa_status_t err;
    uint8_t *p_obj_data = (uint8_t *)&obj->header.info;
    size_t out_len;

    /* TODO: key derive is not supported */

    /* FIXME: should have an IV per object with key diversification */
    /* Get a new IV for each encryption */
    sst_crypto_get_iv(&obj->header.crypto);

    /* Use File ID as a part of the associated data to authenticate
     * the object in the FS. The tag will be stored in the object table and
     * not as a part of the object's data stored in the FS.
     */

    err = sst_crypto_encrypt_and_tag(&obj->header.crypto,
                                     (const uint8_t *)&fid,
                                     sizeof(fid),
                                     p_obj_data,
                                     cur_size,
                                     sst_crypto_buf,
                                     sizeof(sst_crypto_buf),
                                     &out_len,
                                     &idx, sizeof(idx));
    if (err != PSA_SUCCESS || out_len != cur_size) {
        eapp_print("sst_object_auth_encrypt: sst_crypto_encrypt_and tag is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }

    memcpy(p_obj_data, sst_crypto_buf, cur_size);
    return PSA_SUCCESS;
}

static psa_status_t sst_object_auth_decrypt(uint32_t fid,
                                            uint32_t cur_size,
                                            struct sst_object_t *obj, uint32_t idx)
{
    psa_status_t err;
    uint8_t *p_obj_data = (uint8_t *)&obj->header.info;
    size_t out_len;

    //TODO: key derive is not supported
    (void)memcpy(sst_crypto_buf, p_obj_data, cur_size);

    /* Use File ID as a part of the associated data to authenticate
     * the object in the FS. The tag will be stored in the object table and
     * not as a part of the object's data stored in the FS.
     */
    err = sst_crypto_auth_and_decrypt(&obj->header.crypto,
                                      (const uint8_t *)&fid,
                                      sizeof(fid),
                                      sst_crypto_buf,
                                      cur_size,
                                      p_obj_data,
                                      sizeof(*obj) - sizeof(obj->header.crypto),
                                      &out_len, 
                                      &idx, sizeof(idx));
    if(err != PSA_SUCCESS)
    {
        eapp_print("sst_object_auth_decrypt: sst_crypto_auth_and_decrypt is failed \n");
        return err;
    }
    //TODO: key derive is not supported
    // return sst_crypto_destroykey();
    return PSA_SUCCESS;
}

psa_status_t sst_encrypted_object_read(uint32_t fid, struct sst_object_t *obj, uint32_t idx)
{
    psa_status_t err;
    uint32_t decrypt_size;
    int32_t file_size = 0;

    /* Read the encrypted object from the the persistent area */
    //Read the iv from the fs
    char *buf;
    struct stat stat_buf;
    int32_t status;
    status =  fstat(fid, &stat_buf);
    if (status < 0)
    {
        err = PSA_ERROR_GENERIC_ERROR;
        eapp_print("sst_encrypted_object_read: fstat is failed \n");
        return err;
    }
    file_size = stat_buf.st_size;
    // file_size = SST_MAX_OBJECT_DATA_SIZE;
    buf = malloc(file_size);
    status = read(fid, buf, file_size);
    if (status < 0)
    {
        err = PSA_ERROR_GENERIC_ERROR;
        eapp_print("sst_encrypted_object_read: fs read is failed \n");
        return err;
    }
    // Copy the iv,info and data from the disk into obj (encrypted data) 
    memcpy(obj->header.crypto.ref.iv, buf, file_size);

    // Get the decrypt size, only iv is not encrypted in the fs
    decrypt_size = file_size - sizeof(obj->header.crypto.ref.iv);
    /* Decrypt the object data */
    err = sst_object_auth_decrypt(fid, decrypt_size, obj, idx);
    if (err != PSA_SUCCESS) {
        eapp_print("sst_encrypted_object_read: sst_object_auth_decrypt is failed \n");
        return err;
    }
    return PSA_SUCCESS;
}

psa_status_t sst_encrypted_object_write(uint32_t fid, struct sst_object_t *obj, uint32_t idx)
{
    psa_status_t err;
    uint32_t wrt_size;

    /* Compute the encrypt size, contain part of metadata   */
    // wrt_size = SST_ENCRYPT_SIZE(obj->header.info.max_size) +
    //            sizeof(obj->header.crypto.ref.iv);
    wrt_size = SST_ENCRYPT_SIZE(obj->header.info.current_size);
    /* Authenticate and encrypt the object */
    err = sst_object_auth_encrypt(fid, wrt_size, obj, idx);
    if (err != PSA_SUCCESS) {
        eapp_print("sst_encrypted_object_write: sst_object_auth_encrypt is failed \n");
        return err;
    }
    wrt_size += sizeof(obj->header.crypto.ref.iv);

    /* Write the encrypted object to the persistent area. The tag values is not
     * copied as it is stored in the object table.
     */
    write(fid, obj->header.crypto.ref.iv, wrt_size);

    return err;
}