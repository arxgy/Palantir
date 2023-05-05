#ifndef __SBI_IPI_DESTROY_ENCLAVE_H__
#define __SBI_IPI_DESTROY_ENCLAVE_H__

#include <sbi/sbi_types.h>
#include <sbi/sbi_hartmask.h>

struct ipi_destroy_enclave_data_t
{
  ulong host_ptbr;
  int enclave_id;
  struct sbi_hartmask smask;
};

struct sbi_scratch;
int sbi_ipi_destroy_enclave_init(struct sbi_scratch *scratch, bool cold_boot);
int sbi_send_ipi_destroy_enclave(ulong hmask, ulong hbase, struct ipi_destroy_enclave_data_t* ipi_destroy_enclave_data);
void set_ipi_destroy_enclave_and_sync(u32 remote_hart,ulong host_ptbr, int enclave_id);
#endif