#include "ocall.h"
#include "eapp.h"

int eapp_persistency_read_sec(unsigned long sec){
    int ret;
    ret = (int)EAPP_PERSISTENCY_READ_SEC(OCALL_READ_SECT, sec);
    return ret;
}

int eapp_persistency_write_sec(unsigned long sec){
    int ret;
    ret = (int)EAPP_PERSISTENCY_WRITE_SEC(OCALL_WRITE_SECT, sec);
    return ret;
}