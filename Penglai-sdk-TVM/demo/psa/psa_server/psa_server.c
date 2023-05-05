#include "eapp.h"
#include "print.h"
#include "psa/protected_storage.h"
#include "psa/storage_common.h"
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include "psa_server.h"
#include "wolfcrypt/aes.h"
#include "psa_protected_storage.h"
#include "psa_object_server.h"
static void *p_data;

static bool sst_is_init = false;

psa_status_t sst_init(void)
{
    psa_status_t err;

    err = sst_system_prepare();
    return err;
}

static psa_status_t sst_check_init(void)
{
    // TODO: check wether the system is ready
    if (!sst_is_init) {
        if (sst_init() != PSA_SUCCESS) {
          eapp_print("sst_check_init: sst_init is failed \n");
            return PSA_ERROR_GENERIC_ERROR;
        }
        sst_is_init = true;
    }

    return PSA_SUCCESS;
}

//TODO: the client id is equal to the enclave eid, however the eid is no t persistent
static psa_status_t get_caller_client_id(int32_t * client_id)
{
  *client_id = get_caller_id();
  // eapp_print("get_caller_client_id is %d \n", *client_id);
  return PSA_SUCCESS;
}

psa_status_t psa_sst_set_req(psa_call_arg_t * psa_arg)
{
  
  psa_storage_uid_t uid;
  uint32_t data_length;
  int32_t client_id;
  int32_t status;
  psa_storage_create_flags_t create_flags;
  psa_invec *in_vec = (psa_invec *)psa_arg->in_vec;
  psa_callee_outvec *out_vec = (psa_callee_outvec *)psa_arg->out_vec;
  size_t in_len = psa_arg->in_len;
  size_t out_len = psa_arg->out_len;
  if (sst_check_init() != PSA_SUCCESS) {
    eapp_print("psa_Server: sst_check_init is failed\n");
    return PSA_ERROR_GENERIC_ERROR;
  }

  if ((in_len != 3) || (out_len != 0)) {
    /* The number of arguments are incorrect */
    eapp_print("psa_server: error argument of in_len %x and out_len %x\n", in_len, out_len);
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  if (in_vec[0].len != sizeof(psa_storage_uid_t)) {
    /* The input argument size is incorrect */
    eapp_print("psa_server: error uid\n");
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  uid = *((psa_storage_uid_t *)in_vec[0].base);

  p_data = (void *)in_vec[1].base;
  data_length = in_vec[1].len;

  if (in_vec[2].len != sizeof(psa_storage_create_flags_t)) {
    /* The input argument size is incorrect */
    eapp_print("psa_server: error create_flags\n");
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  create_flags = *(psa_storage_create_flags_t *)in_vec[2].base;

  /* Get the caller's client ID */
  status = get_caller_client_id(&client_id);
  if (status != (int32_t)PSA_SUCCESS) {\
    eapp_print("psa_server: get the client id is failed\n");
    return PSA_ERROR_PROGRAMMER_ERROR;
  }
  return psa_sst_set(client_id, uid, data_length, create_flags);
}

psa_status_t psa_sst_get_req(psa_call_arg_t * psa_arg)
{
  
  size_t data_offset;
  uint32_t data_size;
  int32_t client_id;
  psa_storage_uid_t uid;
  int32_t status;
  size_t *p_data_length;
  psa_storage_create_flags_t create_flags;
  psa_invec *in_vec = (psa_invec *)psa_arg->in_vec;
  psa_callee_outvec *out_vec = (psa_callee_outvec *)psa_arg->out_vec;
  size_t in_len = psa_arg->in_len;
  size_t out_len = psa_arg->out_len;

  if (sst_check_init() != PSA_SUCCESS) {
    eapp_print("psa_sst_get_req: sst_check_init is failed \n");
    return PSA_ERROR_GENERIC_ERROR;
  }
  if ((in_len != 2) || (out_len != 1)) {
    /* The number of arguments are incorrect */
    eapp_print("psa_sst_get_req: in_len and out_len is not correct\n");
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  if (in_vec[0].len != sizeof(psa_storage_uid_t)) {
    /* The input argument size is incorrect */
    eapp_print("psa_sst_get_req: in_vec[0].len is not correct\n"); 
    return PSA_ERROR_PROGRAMMER_ERROR;
  }
  uid = *((psa_storage_uid_t *)in_vec[0].base);

  if (in_vec[1].len != sizeof(data_offset)) {
    /* The input argument size is incorrect */
    eapp_print("in_vec[i].len %d, data_offset %d\n", in_vec[1].len, sizeof(data_offset));
    eapp_print("psa_sst_get_req: in_vec[1].len is not correct\n"); 
    return PSA_ERROR_PROGRAMMER_ERROR;
  }
  data_offset = *(uint32_t *)in_vec[1].base;
  p_data = out_vec[0].base;
  data_size = *(out_vec[0].len_addr);
  p_data_length = out_vec[0].len_addr;
  /* Get the caller's client ID */
  status = get_caller_client_id(&client_id);
  if (status != (int32_t)PSA_SUCCESS) {
    eapp_print("psa_sst_get_req: get_caller_client_id is failed\n"); 
    return PSA_ERROR_PROGRAMMER_ERROR;
  }
  // return PSA_CALL_SUCCESS;
  return psa_sst_get(client_id, uid, data_offset, data_size, p_data_length);
}

psa_status_t psa_sst_get_info_req(psa_call_arg_t * psa_arg)
{
  int32_t client_id;
  psa_storage_uid_t uid;
  struct psa_storage_info_t *p_info;
  int32_t tfm_status;
  psa_invec *in_vec = (psa_invec *)psa_arg->in_vec;
  psa_callee_outvec *out_vec = (psa_callee_outvec *)psa_arg->out_vec;
  size_t in_len = psa_arg->in_len;
  size_t out_len = psa_arg->out_len;
  if (sst_check_init() != PSA_SUCCESS) {
    return PSA_ERROR_GENERIC_ERROR;
  }

  if ((in_len != 1) || (out_len != 1)) {
    /* The number of arguments are incorrect */
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  if (in_vec[0].len != sizeof(psa_storage_uid_t)) {
    /* The input argument size is incorrect */
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  uid = *((psa_storage_uid_t *)in_vec[0].base);

  if (*(out_vec[0].len_addr) != sizeof(struct psa_storage_info_t)) {
    /* The output argument size is incorrect */
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  p_info = (struct psa_storage_info_t *)out_vec[0].base;

  /* Get the caller's client ID */
  tfm_status = get_caller_client_id(&client_id);
  if (tfm_status != (int32_t)PSA_SUCCESS) {
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  return psa_sst_get_info(client_id, uid, p_info);
  
  // return PSA_SUCCESS;
}

psa_status_t psa_sst_remove_req(psa_call_arg_t * psa_arg)
{
  int32_t client_id;
  psa_storage_uid_t uid;
  int32_t tfm_status;
  psa_invec *in_vec = (psa_invec *)psa_arg->in_vec;
  psa_callee_outvec *out_vec = (psa_callee_outvec *)psa_arg->out_vec;
  size_t in_len = psa_arg->in_len;
  size_t out_len = psa_arg->out_len;

  if (sst_check_init() != PSA_SUCCESS) {
    return PSA_ERROR_GENERIC_ERROR;
  }

  if ((in_len != 1) ||
    (in_vec[0].len != sizeof(psa_storage_uid_t)) ||
    (out_len != 0)) {
    /* The number of arguments/output argument size are incorrect */
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  uid = *((psa_storage_uid_t *)in_vec[0].base);

  /* Get the caller's client ID */
  tfm_status = get_caller_client_id(&client_id);
  if (tfm_status != (int32_t)PSA_SUCCESS) {
    return PSA_ERROR_PROGRAMMER_ERROR;
  }

  return psa_sst_remove(client_id, uid);
  // return PSA_SUCCESS;
}

psa_status_t psa_sst_get_support_req(psa_call_arg_t * psa_arg)
{
    uint32_t *support_flags;
    psa_invec *in_vec = (psa_invec *)psa_arg->in_vec;
    psa_callee_outvec *out_vec = (psa_callee_outvec *)psa_arg->out_vec;
    size_t in_len = psa_arg->in_len;
    size_t out_len = psa_arg->out_len;

    (void)in_vec;

    if (sst_check_init() != PSA_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    if ((in_len != 0) || (out_len != 1)) {
        /* The number of arguments are incorrect */
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    if (*(out_vec[0].len_addr) != sizeof(*support_flags)) {
        /* The output argument size is incorrect */
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    support_flags = (uint32_t *)out_vec[0].base;

    *support_flags = psa_sst_get_support();

    return PSA_SUCCESS;
}

int EAPP_ENTRY main(){
  unsigned long* args;
  EAPP_RESERVE_REG;
  unsigned long arg0 = args[10];
  void* vaddr = (void*)args[11];
  unsigned long size = args[12];
  // eapp_print("psa server begin to run, vaddr is %lx, size is %lx\n", vaddr, size);

  psa_status_t ret;
  struct call_enclave_arg_t ret_arg;
  ret_arg.req_vaddr = (unsigned long)vaddr;
  ret_arg.req_size = size;
  ret_arg.resp_vaddr = 0;
  ret_arg.resp_size = 0;
  psa_call_arg_t *psa_arg = malloc(sizeof(psa_call_arg_t));
  psa_callee_stub((psa_call_stub_t *)vaddr , (psa_call_arg_t *)psa_arg);
  //dispatch the different type of the psa request
  // eapp_print("psa_server: arg0 %lx\n", arg0);
  switch(arg0)
  {
    case PSA_PS_SET:
      ret = psa_sst_set_req(psa_arg);
      break;
    case PSA_PS_GET:
      ret = psa_sst_get_req(psa_arg);
      break;
    case PSA_PS_GET_INFO:
      ret = psa_sst_get_info_req(psa_arg);
      break;
    case PSA_PS_REMOVE:
      ret = psa_sst_remove_req(psa_arg);
      break;
    case PSA_PS_CREATE:
      break;
    case PSA_PS_SET_EXTENDED:
      break; 
    case PSA_PS_GET_SUPPORT:
      ret = psa_sst_get_support_req(psa_arg);
      break;
  }
  // for (int i = 0; i < psa_arg->out_len; i++)
  // {
  //   eapp_print("psa_server: psa out_vec[%d] %x size %d\n", i, *(int *)(((psa_callee_outvec *)psa_arg->out_vec)[i].base), *(((psa_callee_outvec *)psa_arg->out_vec)[i].len_addr));
  // }
  ret_arg.resp_vaddr = (unsigned long)ret;
  SERVER_RETURN(&ret_arg);
}

psa_status_t sst_req_mngr_read_asset_data(uint8_t *out_data, uint32_t size)
{
  (void)memcpy(out_data, p_data, size);
  return PSA_SUCCESS;
}

psa_status_t sst_req_mngr_write_asset_data(const uint8_t *in_data,
                                   uint32_t size)
{
  (void)memcpy(p_data, in_data, size);
  return PSA_SUCCESS;
}