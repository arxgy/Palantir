#ifndef _SERVER_ENCLAVE_H
#define _SERVER_ENCLAVE_H

#include "sm/enclave.h"
#include "sm/enclave_args.h"

struct server_enclave_t
{
  //FIXME: enclave has its own name now, so it need not to assign a server name to server enclave 
  char server_name[NAME_LEN];
  struct enclave_t* entity;
};

#define SERVERS_PER_METADATA_REGION 100

uintptr_t create_server_enclave(enclave_create_param_t create_args);
uintptr_t destroy_server_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t acquire_server_enclave(char *server_name);
uintptr_t get_caller_id(uintptr_t* regs);
uintptr_t get_server_enclave_attest_report(char* name, uintptr_t *report, uintptr_t nonce);

#endif /* _SERVER_ENCLAVE_H */
