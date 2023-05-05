#include "psa/protected_storage.h"
#include "psa/client.h"
#include "psa_state.h"
#include "eapp.h"
#include "psa_call_stub.h"
#include "string.h" 
#include "print.h"

psa_status_t psa_call_stub(int32_t type, const psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len)
{    
    int ret;
    char server_name[16];
    strcpy(server_name, "psa_server");
    unsigned long server_handle = acquire_enclave(server_name);
    unsigned long size = 0;
    //Calculate the request page size for psa call stub. 
    size = sizeof(psa_call_stub_t) + in_len * sizeof(psa_invec_offset) + out_len * sizeof(psa_outvec_offset);
    for(int i = 0; i<in_len; i++)
    {
        size += in_vec[i].len;
    }
    for(int i = 0; i<out_len; i++)
    {
        size += out_vec[i].len;
    }
    size = ROUNDUP(size, RISCV_PAGE_SIZE);
    psa_call_stub_t *arg_stub = eapp_mmap(NULL, size);
    arg_stub->in_len = in_len;
    arg_stub->out_len = out_len;
    //store the metadata of in_vec in the preserved space of arg_stub, the offset is in_vec_offset;
    arg_stub->in_vec_offset = sizeof(psa_call_stub_t);
    arg_stub->out_vec_offset = sizeof(psa_call_stub_t) + in_len * sizeof(psa_invec_offset);
    memcpy((char *)arg_stub + arg_stub->in_vec_offset, in_vec, in_len * sizeof(psa_invec_offset));
    memcpy((char *)arg_stub + arg_stub->out_vec_offset, out_vec, out_len * sizeof(psa_outvec_offset));
    size_t tmp_offset = 0;
    size_t data_offset = sizeof(psa_call_stub_t) + in_len * sizeof(psa_invec_offset) + out_len * sizeof(psa_outvec_offset);
    //Store the original in/out data into the relay page, which is prepared to transfer to the psa server enclave
    for(int i = 0; i<in_len; i++)
    {
        size_t tmp_in_offset = data_offset + tmp_offset;
        ((psa_invec_offset *)((arg_stub->in_vec_offset) + (char *)arg_stub))[i].offset = data_offset + tmp_offset;
        ((psa_invec_offset *)((arg_stub->in_vec_offset) + (char *)arg_stub))[i].len = in_vec[i].len;
        tmp_offset += in_vec[i].len;
        memcpy((char *)arg_stub + tmp_in_offset, in_vec[i].base, in_vec[i].len);
    }
    for(int i = 0; i<out_len; i++)
    {
        ((psa_outvec_offset *)((arg_stub->out_vec_offset) + (char *)arg_stub))[i].offset = data_offset + tmp_offset;
        ((psa_outvec_offset *)((arg_stub->out_vec_offset) + (char *)arg_stub))[i].len = out_vec[i].len;
        tmp_offset += in_vec[i].len;
    }

    struct call_enclave_arg_t call_arg;
    call_arg.req_arg = type;
    call_arg.req_vaddr = (unsigned long)arg_stub;
    call_arg.req_size = size;
    ret = call_enclave(server_handle, &call_arg);
    arg_stub = (psa_call_stub_t *)call_arg.req_vaddr;
    //copy the responding value into the out vector
    for(int i = 0; i < out_len; i++){
        
        memcpy(out_vec[i].base, (char *)arg_stub + ((psa_outvec_offset *)((arg_stub->out_vec_offset) + (char *)arg_stub))[i].offset, 
        ((psa_outvec_offset *)((arg_stub->out_vec_offset) + (char *)arg_stub))[i].len);
        out_vec[i].len = ((psa_outvec_offset *)((arg_stub->out_vec_offset) + (char *)arg_stub))[i].len;
    }
    if (ret <0 )
    {
        eapp_print("EAPP LIB: psa_call_stub: call enclave is failed\n");
        return PSA_ERROR_GENERIC_ERROR;
    }
    return call_arg.resp_val;
}