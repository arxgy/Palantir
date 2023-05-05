#ifndef  _EAPP_PSA_SERVER
#define _EAPP_PSA_SERVER
#include "psa/protected_storage.h"
#include "psa/client.h"
#include "psa_state.h"
#include "psa_call_stub.h"

psa_status_t psa_callee_stub(psa_call_stub_t* arg_stub, psa_call_arg_t *psa_arg);
psa_status_t sst_req_mngr_read_asset_data(uint8_t *out_data, uint32_t size);
psa_status_t sst_req_mngr_write_asset_data(const uint8_t *in_data, uint32_t size);
#endif