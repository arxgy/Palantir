#include "ocall.h"
#include "eapp.h"
#include "print.h"

int eapp_create_enclave(unsigned long ocall_param_vaddr)
{
    int retval = 0;
    retval = EAPP_CREATE_ENCLAVE(OCALL_CREATE_ENCLAVE, ocall_param_vaddr);
    return retval;
}

int eapp_attest_enclave(unsigned long ocall_param_vaddr)
{
    int retval = 0;
    retval = EAPP_ATTEST_ENCLAVE(OCALL_ATTEST_ENCLAVE, ocall_param_vaddr);
    return retval;
}

int eapp_run_enclave(unsigned long ocall_param_vaddr)
{
    int retval = 0;
    retval = EAPP_RUN_ENCLAVE(OCALL_RUN_ENCLAVE, ocall_param_vaddr);
    return retval;
}

int eapp_stop_enclave(unsigned long ocall_param_vaddr)
{
    int retval = 0;
    retval = EAPP_STOP_ENCLAVE(OCALL_STOP_ENCLAVE, ocall_param_vaddr);
    return retval;
}

int eapp_resume_enclave(unsigned long ocall_param_vaddr)
{
    int retval = 0;
    retval = EAPP_RESUME_ENCLAVE(OCALL_RESUME_ENCLAVE, ocall_param_vaddr);
    return retval;
}

int eapp_destroy_enclave(unsigned long eid)
{
    int retval = 0;
    retval = EAPP_DESTROY_ENCLAVE(OCALL_DESTROY_ENCLAVE, eid);
    return retval;
}

int eapp_inspect_enclave(unsigned long ocall_param_vaddr)
{
    int retval = 0;
    retval = EAPP_INSPECT_ENCLAVE(OCALL_INSPECT_ENCLAVE, ocall_param_vaddr);
    return retval;
}

int eapp_pause_enclave(unsigned long ocall_param_vaddr)
{
    int retval = 0;
    retval = EAPP_PAUSE_ENCLAVE(OCALL_PAUSE_ENCLAVE, ocall_param_vaddr);
    return retval;
}