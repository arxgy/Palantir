/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 *   Atish Patra <atish.patra@wdc.com>
 */

#include <sbi/sbi_ecall.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_version.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>
#include "sm/sm.h"


static int sbi_ecall_penglai_handler(unsigned long extid, unsigned long funcid,
				  unsigned long *args, unsigned long *out_val,
				  struct sbi_trap_info *out_trap)
{
  uintptr_t arg0 = args[10], arg1 = args[11], arg2 = args[12], arg3 = args[13], arg4 = args[14], retval;
  csr_write(CSR_MEPC, args[32] + 4);
  switch (funcid) {
    case SBI_SET_PTE:
      retval = sm_set_pte(arg0, (uintptr_t*)arg1, arg2, arg3);
      break;
    case SBI_SM_INIT:
      retval = sm_sm_init(arg0, arg1, arg2, arg3, arg4);
      break;
    case SBI_SM_PT_AREA_SEPARATION:
      retval = sm_pt_area_separation(arg0, arg1);
      break;
    case SBI_SM_MAP_PTE:
      retval = sm_map_pte((uintptr_t *)arg0, (uintptr_t *)arg1);
      break;
    case SBI_MEMORY_EXTEND:
      retval = sm_mm_extend(arg0, arg1);
      break;
    case SBI_CREATE_ENCLAVE:
      retval = sm_create_enclave(arg0);
      break;
    case SBI_RUN_ENCLAVE:
      retval = sm_run_enclave(args, arg0, arg1);
      break;
    case SBI_STOP_ENCLAVE:
      retval = sm_stop_enclave(args, arg0);
      break;
    case SBI_RESUME_ENCLAVE:
      retval = sm_resume_enclave(args, arg0, arg1);
      break;
    case SBI_DESTROY_ENCLAVE:
      retval = sm_destroy_enclave(args, arg0);
      break;
    case SBI_ATTEST_ENCLAVE:
      retval = sm_attest_enclave(arg0, arg1, arg2);
      break;
    case SBI_CREATE_SERVER_ENCLAVE:
      retval = sm_create_server_enclave(arg0);
      break;
    case SBI_CREATE_SHADOW_ENCLAVE:
      retval = sm_create_shadow_enclave(arg0);
      break;
    case SBI_RUN_SHADOW_ENCLAVE:
      retval = sm_run_shadow_enclave(args, arg0, arg1);
      break;
    case SBI_ATTEST_SHADOW_ENCLAVE:
      retval = sm_attest_shadow_enclave(arg0, arg1, arg2);
      break;
    case SBI_DESTROY_SHADOW_ENCLAVE:
      retval = sm_destroy_shadow_enclave(args, arg0);
      break;
    case SBI_DESTROY_SERVER_ENCLAVE:
      retval = sm_destroy_server_enclave(args, arg0);
      break;
    case SBI_SCHRODINGER_INIT:
      retval = sm_schrodinger_init(arg0, arg1);
      break;
    case 84:
      retval = sm_print(arg0, arg1);
      break;

	default:
		retval = SBI_ENOTSUPP;
	}
  args[32] = csr_read(CSR_MEPC);
  args[33] = csr_read(CSR_MSTATUS);
  *out_val = retval;
	return retval;
}

struct sbi_ecall_extension ecall_penglai = {
	.extid_start = SBI_EXT_PENGLAI_HOST,
	.extid_end = SBI_EXT_PENGLAI_HOST,
	.handle = sbi_ecall_penglai_handler,
};
