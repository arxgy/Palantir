#include "psa_object_table.h"
#include "psa_encrypted_object.h"
#include "psa_crypto_interface.h"
//TODO: haven't finished

/* Idx to file_name mapping*/
uint32_t table_idx = 0;
char *MAGIC_OBJECT_CHAR="/magic_%d.txt";
char *MAGIC_TABLE_CHAR="/table.txt";
char *MAGIC_NVC="/nvc_%d.txt";

psa_status_t sst_init_nv_counter(enum psa_nv_counter_t counter_id)
{
    psa_status_t err;

    size_t ret = NULL;
    uint32_t nvc = 0;

    /* Read obj_table from the persistent stoarge */
    char file_name[PSA_FILE_LEN];
    sprintf(file_name, MAGIC_NVC, counter_id);

    FILE*fp=fopen(file_name, "w+");
    if(!fp)
    {
        eapp_print("sst_init_nv_counter: fopen is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }

    ret = fwrite(&nvc, sizeof(nvc), 1, fp);
    if (!ret)
    {
        eapp_print("sst_increment_nv_counter: fwrite is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }
   
    fclose(fp);

    return PSA_SUCCESS;
}

psa_status_t sst_read_nv_counter(enum psa_nv_counter_t counter_id,
                                 uint32_t *val)
{
    psa_status_t err;

    size_t ret = NULL;
    uint32_t nvc;
    /* Read obj_table from the persistent stoarge */
    char file_name[PSA_FILE_LEN];
    sprintf(file_name, MAGIC_NVC, counter_id);

    FILE*fp=fopen(file_name, "w+");
    if(!fp)
    {
        eapp_print("sst_read_nv_counter: fopen is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }
    ret = fread(&nvc, sizeof(nvc), 1, fp);
    if (!ret)
    {
        eapp_print("sst_read_nv_counter: fread is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }

    fclose(fp);
    *val = nvc;

    return PSA_SUCCESS;
}

psa_status_t sst_increment_nv_counter(enum psa_nv_counter_t counter_id)
{
    psa_status_t err;

    size_t ret = NULL;
    uint32_t nvc;
    /* Read obj_table from the persistent stoarge */
    char file_name[PSA_FILE_LEN];
    sprintf(file_name, MAGIC_NVC, counter_id);

    FILE*fp=fopen(file_name, "w+");
    if(!fp)
    {
        eapp_print("sst_increment_nv_counter: fopen is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }
    ret = fread(&nvc, sizeof(nvc), 1, fp);
    if (!ret)
    {
        eapp_print("sst_increment_nv_counter: fread is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }
    nvc++;
    fseek(fp, SEEK_SET, 0);
    ret = fwrite(&nvc, sizeof(nvc), 1, fp);
    if (!ret)
    {
        eapp_print("sst_increment_nv_counter: fwrite is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }
   
    fclose(fp);

    return PSA_SUCCESS;
}

psa_status_t sst_object_delete_from_persistent_storage(uint32_t idx)
{
    int fd, ret;
    char file_name[PSA_FILE_LEN];
    sprintf(file_name, MAGIC_OBJECT_CHAR, idx+SST_OBJ_TABLE_IDX_1+1);
    ret = unlink(file_name);
    if (ret < 0)
    {
        eapp_print("sst_object_delete_from_persistent_storage: unlink is failed, idx is %d\n", idx);
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

uint32_t SST_OBJECT_FS_ID(uint32_t idx)
{
    int fd;
    char file_name[PSA_FILE_LEN];
    sprintf(file_name, MAGIC_OBJECT_CHAR, idx+SST_OBJ_TABLE_IDX_1+1);
    fd = open(file_name, O_RDWR| O_CREAT);
    if (fd < 0)
    {
        eapp_print("SST_OBJECT_FS_ID is failed \n");
        return fd;
    }
    return fd;  
}

//TODO: the file name of the obj_table is  east to guess
/* Store the obj_table in the table.txt file*/
psa_status_t sst_object_table_existed(struct sst_obj_table_init_ctx_t *init_ctx)
{
    psa_status_t err;
    char *ret = NULL;
    /* Read obj_table from the persistent stoarge */
    char file_name[PSA_FILE_LEN];
    sprintf(file_name, MAGIC_TABLE_CHAR);
    
    FILE*fp=fopen(file_name, "r");
    if(!fp)
    {
        eapp_print("sst_object_table_existed: init table is not existed \n");
        sst_init_nv_counter(PLAT_NV_COUNTER_1);
    
        return PSA_ERROR_GENERIC_ERROR;
    }
    fclose(fp);
    return PSA_SUCCESS;
}

psa_status_t sst_object_table_fs_read_table(struct sst_obj_table_init_ctx_t *init_ctx)
{
    psa_status_t err;
    char *ret = NULL;
    /* Read obj_table from the persistent stoarge */
    char file_name[PSA_FILE_LEN];
    sprintf(file_name, MAGIC_TABLE_CHAR);
    struct stat st;
    FILE*fp=fopen(file_name, "w+");
    if(!fp)
    {
        eapp_print("sst_object_table_fs_read_table: is fopen is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }
    int status = stat(file_name, &st);
    if(status){
        eapp_print("sst_object_table_fs_read_table: file stat is failed\n");
    }
    int size=st.st_size;
    ret = fgets((uint8_t *)init_ctx->p_table[SST_OBJ_TABLE_IDX_0], size, fp);
    if (!ret)
    {
        eapp_print("sst_object_table_fs_read_table: fgets is failed %d\n", ret);
        init_ctx->table_state[SST_OBJ_TABLE_IDX_0] = SST_OBJ_TABLE_INVALID;
        return PSA_ERROR_GENERIC_ERROR;
    }
    fclose(fp);
    return PSA_SUCCESS;
}

psa_status_t sst_object_table_nvc_generate_auth_tag(
                                              uint32_t nvc_1,
                                              struct sst_obj_table_t *obj_table)
{
    struct sst_crypto_assoc_data_t assoc_data;
    union sst_crypto_t *crypto = &obj_table->crypto;

    /* Get new IV */
    sst_crypto_get_iv(crypto);

    assoc_data.nv_counter = nvc_1;
    (void)memcpy(assoc_data.obj_table_data,
                     SST_CRYPTO_ASSOCIATED_DATA(crypto),
                     SST_OBJ_TABLE_AUTH_DATA_SIZE);

    return sst_crypto_generate_auth_tag(crypto, (const uint8_t *)&assoc_data,
                                        SST_CRYPTO_ASSOCIATED_DATA_LEN, &table_idx, sizeof(table_idx));
}

static psa_status_t sst_object_table_authenticate(struct sst_obj_table_init_ctx_t *init_ctx)
{
    struct sst_crypto_assoc_data_t assoc_data;
    union sst_crypto_t *crypto = &init_ctx->p_table[SST_OBJ_TABLE_IDX_0]->crypto;
    psa_status_t err;

    /* Init associated data with NVC 1 */
    //TODO: nvc is remain zero in this implemantation
    err = sst_read_nv_counter(PLAT_NV_COUNTER_1, &init_ctx->nvc_1);
    if (err != PSA_SUCCESS) {
        return err;
    }
    assoc_data.nv_counter = init_ctx->nvc_1;
    (void)memcpy(assoc_data.obj_table_data,
                     SST_CRYPTO_ASSOCIATED_DATA(crypto),
                     SST_OBJ_TABLE_AUTH_DATA_SIZE);

    err = sst_crypto_authenticate(crypto, (const uint8_t *)&assoc_data,
                                  SST_CRYPTO_ASSOCIATED_DATA_LEN, &table_idx, sizeof(table_idx));
    if (err == PSA_SUCCESS) {
        init_ctx->table_state[SST_OBJ_TABLE_IDX_0] = SST_OBJ_TABLE_NVC_1_VALID;
        return err;
    }
    eapp_print("sst_object_table_authenticate: sst_crypto_authenticate is failed\n");
    return err;

}

void sst_object_table_validate_version(struct sst_obj_table_init_ctx_t *init_ctx)
{
    /* Looks for exact version number. */
    if (SST_OBJECT_SYSTEM_VERSION !=
        init_ctx->p_table[SST_OBJ_TABLE_IDX_0]->version) {
        init_ctx->table_state[SST_OBJ_TABLE_IDX_0] = SST_OBJ_TABLE_INVALID;
    }
}

psa_status_t sst_object_table_init(uint8_t *obj_data)
{
    psa_status_t err;
    struct sst_obj_table_init_ctx_t init_ctx = {
        //assign the pointer of  sst_obj_table_ctx.object to init_ctx.p_table
        .p_table = {&sst_obj_table_ctx.obj_table, NULL},
        .table_state = {SST_OBJ_TABLE_VALID, SST_OBJ_TABLE_VALID},
        .nvc_1 = 0U,
        .nvc_3 = 0U,
    };
    //temporary store the object table into the obj_data, data will be
    // cleaned up when be used for the object system in the first time
    init_ctx.p_table[SST_OBJ_TABLE_IDX_1] = (struct sst_obj_table_t *)obj_data;

    /* Read table from the file system */
    err = sst_object_table_existed(&init_ctx);
    if (err == PSA_SUCCESS)
    {
        int status;
        status = sst_object_table_fs_read_table(&init_ctx);
        if (status != PSA_SUCCESS)
        {
            eapp_print("sst_object_table_init: sst_object_table_fs_read_table is failed \n");
        }

        status = sst_object_table_authenticate(&init_ctx);
        if (status != PSA_SUCCESS)
        {
            eapp_print("sst_object_table_init: sst_object_table_authenticate is failed \n");
        }
        sst_object_table_validate_version(&init_ctx);
        sst_crypto_set_iv(&sst_obj_table_ctx.obj_table.crypto);
    }
    else
    {
        eapp_print("sst_object_table_init: is un-initialized\n");
        memset(&sst_obj_table_ctx, 0, sizeof(sst_obj_table_ctx));
    }
    

    return PSA_SUCCESS;
}

static psa_status_t sst_get_object_entry_idx(psa_storage_uid_t uid,
                                             int32_t client_id,
                                             uint32_t *idx)
{
    uint32_t i;
    struct sst_obj_table_t *p_table = &sst_obj_table_ctx.obj_table;
    for (i = 0; i < SST_OBJ_TABLE_ENTRIES; i++) {
        if (p_table->obj_db[i].uid == uid
            && p_table->obj_db[i].client_id == client_id) {
            *idx = i;
            return PSA_SUCCESS;
        }
    }
    eapp_print("Warning: The object is not existed \n");
    return PSA_ERROR_DOES_NOT_EXIST;
}

psa_status_t sst_object_table_get_obj_tbl_info(psa_storage_uid_t uid,
                                               int32_t client_id,
                                      struct sst_obj_table_info_t *obj_tbl_info, uint32_t *old_id)
{
    psa_status_t err;
    uint32_t idx;
    struct sst_obj_table_t *p_table = &sst_obj_table_ctx.obj_table;
    //get the obj id from the object table
    err = sst_get_object_entry_idx(uid, client_id, &idx);
    if (err != PSA_SUCCESS) {
        return err;
    }
    *old_id = idx;
    //convert the obj id into the fd, and refill the obj_info (fid and tag) 
    obj_tbl_info->fid = SST_OBJECT_FS_ID(idx);

    (void)memcpy(obj_tbl_info->tag, p_table->obj_db[idx].tag,
                     SST_TAG_LEN_BYTES);

    return PSA_SUCCESS;
}

psa_status_t sst_table_free_idx(uint32_t idx_num, uint32_t *idx)
{
    uint32_t i;
    uint32_t last_free = 0;
    struct sst_obj_table_t *p_table = &sst_obj_table_ctx.obj_table;

    if (idx_num == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    for (i = 0; i < SST_OBJ_TABLE_ENTRIES && idx_num > 0; i++) {
        if (p_table->obj_db[i].uid == SST_INVALID_UID) {
            last_free = i;
            idx_num--;
        }
    }

    if (idx_num != 0) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    } else {
        *idx = last_free;
        return PSA_SUCCESS;
    }
}

psa_status_t sst_object_table_get_free_fid(uint32_t fid_num,
                                           uint32_t *p_fid, uint32_t *tmp_id)
{
    psa_status_t err;
    uint32_t fid;
    uint32_t idx;
    err = sst_table_free_idx(fid_num, &idx);
    if (err != PSA_SUCCESS) {
        return err;
    }

    /* There first two file IDs are reserved for the active table
     * and scratch table files.
     */
    fid = SST_OBJECT_FS_ID(idx);
    //TODO: check whether there is a fid in the persistency area
    *p_fid = fid;
    *tmp_id = idx;
    return PSA_SUCCESS;
}

static void sst_table_delete_entry(uint32_t idx)
{
    struct sst_obj_table_t *p_table = &sst_obj_table_ctx.obj_table;

    p_table->obj_db[idx].uid = SST_INVALID_UID;
    p_table->obj_db[idx].client_id = 0;

    memset(p_table->obj_db[idx].tag, SST_DEFAULT_EMPTY_BUFF_VAL,
                     SST_OBJECTS_TABLE_ENTRY_SIZE);
}

psa_status_t sst_object_table_save_table(struct sst_obj_table_t *obj_table)
{
    psa_status_t err;
    /* TODO: nvm counter is unfinished */
    uint32_t nvc_1 = 0;
    err = sst_increment_nv_counter(PLAT_NV_COUNTER_1);
    if (err != PSA_SUCCESS) {
        return err;
    }

    err = sst_read_nv_counter(PLAT_NV_COUNTER_1, &nvc_1);
    if (err != PSA_SUCCESS) {
        return err;
    }

//TODO: key derive is not supported

    /* Generate authentication tag from the current table content and SST
     * NV counter 1.
     */
    err = sst_object_table_nvc_generate_auth_tag(nvc_1, obj_table);

    if (err != PSA_SUCCESS) {
        eapp_print("sst_object_table_save_table: sst_object_table_nvc_generate_auth_tag is failed \n");
        return err;
    }
    /* store the whol table into the persistency disk, both data and crypto metadata. Later, we can use the nv to
     * re-calculate the sst_table tag, and compare the tag store in the persistency disk     
     */
    int tbl_fid;
    char file_name[PSA_FILE_LEN];
    sprintf(file_name, MAGIC_TABLE_CHAR);
    tbl_fid = open(file_name, O_RDWR| O_CREAT);
    if (tbl_fid < 0)
    {
        eapp_print("sst_object_table_get_free_fid: open the obj_table is failed");
        return PSA_ERROR_GENERIC_ERROR;
    }
    /* write the table metadata into persistency storage*/
    err = write(tbl_fid, obj_table, sizeof(struct sst_obj_table_t));
    if (err < 0)
    {
        eapp_print("sst_object_table_get_free_fid: write the obj_tbl is failed \n");
        err = PSA_ERROR_GENERIC_ERROR;
    }
    close(tbl_fid);

    struct stat st;
    int status = stat(file_name, &st);
    if(!status){
        eapp_print("stat succeed: file length: %d\n",st.st_size);
    }

    //TODO：unfinish function
    /* we should align the nvc_1 to nvc_2 */
    return PSA_SUCCESS;
}

psa_status_t sst_object_table_set_obj_tbl_info(psa_storage_uid_t uid,
                                               int32_t client_id,
                                const struct sst_obj_table_info_t *obj_tbl_info, uint32_t tmp_id)
{
    psa_status_t err;
    uint32_t idx = 0;
    uint32_t backup_idx = 0;
    struct sst_obj_table_entry_t backup_entry = {
        .tag = {0U},
        /* SST_ENCRYPTION */
        .uid = SST_INVALID_UID,
        .client_id = 0,
    };
    struct sst_obj_table_t *p_table = &sst_obj_table_ctx.obj_table;
    //check whether idx is existed
    err = sst_get_object_entry_idx(uid, client_id, &backup_idx);
    if (err == PSA_SUCCESS) {
        /* If an entry exists for this UID, it creates a backup copy in case
         * an error happens while updating the new table in the filesystem.
         */
        (void)memcpy(&backup_entry, &p_table->obj_db[backup_idx],
                         SST_OBJECTS_TABLE_ENTRY_SIZE);

        /* Deletes old object information if it exist in the table */
        eapp_print("sst_object_table_set_obj_tbl_info: uid is existed, remove the old idx %d from the obj_table\n", backup_idx);
        sst_table_delete_entry(backup_idx);
    }
    eapp_print("sst_object_table_set_obj_tbl_info: idx %d, uid %d, client_id %d", tmp_id, uid, client_id);
    idx = tmp_id;
    p_table->obj_db[idx].uid = uid;
    p_table->obj_db[idx].client_id = client_id;

    /* Add new object information */
    (void)memcpy(p_table->obj_db[idx].tag, obj_tbl_info->tag,
                     SST_TAG_LEN_BYTES);

    err = sst_object_table_save_table(p_table);
    if (err != PSA_SUCCESS) {
        if (backup_entry.uid != SST_INVALID_UID) {
            /* Rollback the change in the table */
            (void)memcpy(&p_table->obj_db[backup_idx], &backup_entry,
                             SST_OBJECTS_TABLE_ENTRY_SIZE);
        }
        eapp_print("sst_object_table_set_obj_tbl_info: sst_object_table_save_table is failed, recover the idx %d\n", backup_idx);
        sst_table_delete_entry(idx);
    }

    return err;
}

psa_status_t sst_object_table_delete_object(psa_storage_uid_t uid,
                                            int32_t client_id)
{
    uint32_t backup_idx = 0;
    struct sst_obj_table_entry_t backup_entry;
    psa_status_t err;
    struct sst_obj_table_t *p_table = &sst_obj_table_ctx.obj_table;

    /* Create a backup copy in case an error happens while updating the new
     * table in the filesystem.
     */
    err = sst_get_object_entry_idx(uid, client_id, &backup_idx);
    if (err != PSA_SUCCESS) {
        /* If the object is not present in the table, it returns an error
         * to not generate a new file where the table content is the same.
         * Otherwise, that could be used by an attacker to get the encryption
         * key.
         */
        return err;
    }

    (void)memcpy(&backup_entry, &p_table->obj_db[backup_idx],
                     SST_OBJECTS_TABLE_ENTRY_SIZE);

    sst_table_delete_entry(backup_idx);

    err = sst_object_table_save_table(p_table);
    if (err != PSA_SUCCESS) {
       /* Rollback the change in the table */
       (void)memcpy(&p_table->obj_db[backup_idx], &backup_entry,
                        SST_OBJECTS_TABLE_ENTRY_SIZE);
    }

    return err;
}