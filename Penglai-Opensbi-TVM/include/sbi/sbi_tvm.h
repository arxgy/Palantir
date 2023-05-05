#ifndef __SBI_TVM_H__
#define __SBI_TVM_H__

#include <sbi/sbi_types.h>
#include <sbi/sbi_hartmask.h>

struct tvm_data_t
{
  struct sbi_hartmask smask;
};

struct sbi_scratch;
int sbi_tvm_init(struct sbi_scratch *scratch, bool cold_boot);
int sbi_send_tvm(ulong hmask, ulong hbase, struct tvm_data_t* tvm_data);
void set_tvm_and_sync();
#endif