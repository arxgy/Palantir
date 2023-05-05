#include "psa_server.h"
#include "eapp.h"
#include "string.h" 
#include "print.h"
#include "stdlib.h"

/*
 * psa_callee_stub: the stub function for the psa callee/serve. It will be invoked by the psa server
 * and parse the psa request argument,
 * 
 * arg_stub @ the arg pointer indicate the argument address in the relay page
 * psa_arg @ the preserved space for psa request argument.
 */
psa_status_t psa_callee_stub(psa_call_stub_t* arg_stub, psa_call_arg_t *psa_arg)
{    
    int ret = 0;
    psa_invec *recv_psa_invec;
    psa_callee_outvec *recv_psa_outvec;
    psa_invec_offset *recv_psa_invec_offset = (psa_invec_offset *)(arg_stub->in_vec_offset + (char *)arg_stub);
    psa_outvec_offset *recv_psa_outvec_offset = (psa_outvec_offset *)(arg_stub->out_vec_offset + (char *)arg_stub);
    size_t psa_invec_len = arg_stub->in_len;
    size_t psa_outvec_len = arg_stub->out_len;
    recv_psa_invec = (psa_invec *)malloc(sizeof(psa_invec) * psa_invec_len);
    recv_psa_outvec = (psa_callee_outvec *)malloc(sizeof(psa_callee_outvec) * psa_outvec_len);
    for (int i = 0; i < psa_invec_len; i++)
    {
        //record the invec address in the relay page
        recv_psa_invec[i].base = recv_psa_invec_offset[i].offset + (char *)arg_stub;
        recv_psa_invec[i].len = recv_psa_invec_offset[i].len;
        // eapp_print("recv_psa_invec[%d] is %s\n", i, recv_psa_invec[i].base);
    }
    for (int i = 0; i < psa_outvec_len; i++)
    {
        //record the outvec address in the relay page, later we can directly store the responding date into the relay page
        recv_psa_outvec[i].base = recv_psa_outvec_offset[i].offset + (char *)arg_stub;
        recv_psa_outvec[i].len_addr = &(recv_psa_outvec_offset[i].len);
    }
    psa_arg->in_len = psa_invec_len;
    psa_arg->out_len = psa_outvec_len;
    psa_arg->in_vec = recv_psa_invec;
    psa_arg->out_vec = recv_psa_outvec;
    // eapp_print("psa_callee_stub: psa_arg->in_len %x\n", psa_arg->in_len);
    return ret;
}