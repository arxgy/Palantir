/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_trap.h>
#include "sm/enclave.h"
#include "sm/sm.h"
#include "sm/syscall.h"

//All hards need to ne notified
int CPU_IN_CRITICAL=0xFFFFFFFF;
// The hart needs to flush TLB
int CPU_FLUSH_TAG=0x0;
int CPU_NEED_FLUSH[MAX_HARTS] = {0, };

// The hart needs to destroy an enclave
bool NEED_DESTORY_ENCLAVE[MAX_HARTS] = {0, };
// The hart needs to stop an enclave
bool NEED_STOP_ENCLAVE[MAX_HARTS] = {0, };

spinlock_t cpu_in_critical_lock = SPINLOCK_INIT;

#define REMOVE_CPU_FROM_NOTIFICATION(hartid) CPU_IN_CRITICAL&(~(1<<hartid))
#define CPU_ENABLE_NOTIFICATION(hartid) CPU_IN_CRITICAL|(hartid)

#define SET_FLUSH_TAG(hartid) CPU_FLUSH_TAG|(hartid)
#define REMOVE_FLUSH_TAG(hartid) CPU_FLUSH_TAG&(~(1<<hartid))

u16 sbi_ecall_version_major(void)
{
	return SBI_ECALL_VERSION_MAJOR;
}

u16 sbi_ecall_version_minor(void)
{
	return SBI_ECALL_VERSION_MINOR;
}

static unsigned long ecall_impid = SBI_OPENSBI_IMPID;

unsigned long sbi_ecall_get_impid(void)
{
	return ecall_impid;
}

void sbi_ecall_set_impid(unsigned long impid)
{
	ecall_impid = impid;
}

static SBI_LIST_HEAD(ecall_exts_list);

struct sbi_ecall_extension *sbi_ecall_find_extension(unsigned long extid)
{
	struct sbi_ecall_extension *t, *ret = NULL;

	sbi_list_for_each_entry(t, &ecall_exts_list, head) {
		if (t->extid_start <= extid && extid <= t->extid_end) {
			ret = t;
			break;
		}
	}

	return ret;
}

int sbi_ecall_register_extension(struct sbi_ecall_extension *ext)
{
	struct sbi_ecall_extension *t;

	if (!ext || (ext->extid_end < ext->extid_start) || !ext->handle)
		return SBI_EINVAL;

	sbi_list_for_each_entry(t, &ecall_exts_list, head) {
		unsigned long start = t->extid_start;
		unsigned long end = t->extid_end;
		if (end < ext->extid_start || ext->extid_end < start)
			/* no overlap */;
		else
			return SBI_EINVAL;
	}

	SBI_INIT_LIST_HEAD(&ext->head);
	sbi_list_add_tail(&ext->head, &ecall_exts_list);

	return 0;
}

void sbi_ecall_unregister_extension(struct sbi_ecall_extension *ext)
{
	bool found = FALSE;
	struct sbi_ecall_extension *t;

	if (!ext)
		return;

	sbi_list_for_each_entry(t, &ecall_exts_list, head) {
		if (t == ext) {
			found = TRUE;
			break;
		}
	}

	if (found)
		sbi_list_del_init(&ext->head);
}

int enclave_call_trap(struct sbi_trap_regs* regs)
{
	unsigned long retval = 0;

	if(check_in_enclave_world() < 0)
	{
		retval = SBI_ERR_FAILED;
		regs->mepc += 4;
		regs->mstatus = csr_read(CSR_MSTATUS);
		regs->a0 = retval;
		sbi_bug("M mode: enclave_call_trap: check in enclave world is failed \n");
		return 0;
	}

	if (regs->a6 != SBI_EXT_PENGLAI_ENCLAVE)
	{
		if (regs->a7 == __NR_ioctl)
		{
			regs->a0 = retval;
			regs->mepc = regs->mepc + 4;
			regs->mstatus = csr_read(CSR_MSTATUS);
			return 0;
		}
		destroy_enclave((uintptr_t *)regs, get_curr_enclave_id());
		regs->mepc = csr_read(CSR_MEPC);
		regs->mstatus = csr_read(CSR_MSTATUS);
		regs->a0 = -1;
		sbi_bug("M mode: enclave_call_trap: illegal user ecall\n");
		return 0;
	}

	spin_lock(&cpu_in_critical_lock);
	CPU_IN_CRITICAL = REMOVE_CPU_FROM_NOTIFICATION(current_hartid());
	spin_unlock(&cpu_in_critical_lock);
	uintptr_t n = regs->a7;
	csr_write(CSR_MEPC, regs->mepc + 4);
	uintptr_t arg0 = regs->a0, arg1 = regs->a1, arg2 = regs->a2, arg3 = regs->a3;
	sbi_printf("[sbi] case of OCALL trap: [%lu]\n", n);
	switch (n)
	{
		case SBI_EXIT_ENCLAVE:
			retval = sm_exit_enclave((uintptr_t*)regs, arg0);
			sbi_printf("[sbi] out of SBI_EXIT_ENCLAVE\n");
			break;
		case SBI_ENCLAVE_OCALL:
			// sbi_printf("[sbi] into SBI_ENCLAVE_OCALL\n");
			retval = sm_enclave_ocall((uintptr_t*)regs, arg0, arg1, arg2, arg3);
			// sbi_printf("[sbi] out SBI_ENCLAVE_OCALL\n");
			break;
		case SBI_ACQUIRE_SERVER:
			retval = sm_server_enclave_acquire((uintptr_t*)regs, arg0);
			break;
		case SBI_GET_CALLER_ID:
			retval = sm_get_caller_id((uintptr_t*)regs);
			break;
		case SBI_GET_ENCLAVE_ID:
			retval = sm_get_enclave_id((uintptr_t*)regs);
			break;
		case SBI_CALL_ENCLAVE:
			retval = sm_call_enclave((uintptr_t*)regs, arg0, arg1);
			break;
		case SBI_ENCLAVE_RETURN:
			retval = sm_enclave_return((uintptr_t*)regs, arg0);
			break;
		case SBI_ASYN_ENCLAVE_CALL:
			retval = sm_asyn_enclave_call((uintptr_t*)regs, arg0, arg1);
			break;
		case SBI_SPLIT_MEM_REGION:
			retval = sm_split_mem_region((uintptr_t*)regs, arg0, arg1, arg2);
			break;
		case SBI_YIELD:
			retval = sm_handle_yield((uintptr_t*)regs);
			break;
		case SBI_GET_REPORT:
			retval = sm_get_report((uintptr_t*)regs, (char*)arg0, (uintptr_t*)arg1, arg2);
			break;
		case SBI_SHM_ATTACH:
			retval = sm_shm_attatch((uintptr_t*)regs, arg0);
			break;
		case SBI_SHM_STAT:
			retval = sm_shm_stat((uintptr_t*)regs, arg0, arg1);
			break;
		case SBI_GET_KEY:
			retval = sm_get_key((uintptr_t*)regs, arg0, (uintptr_t*)arg1, arg2);
			break;
		default:
			retval = SBI_ERR_FAILED;
			sbi_bug("M mode: enclave_call_trap: unsupported ecall number %lx from enclave\n", n);
			if(check_in_enclave_world() == 0)
			{
				destroy_enclave((uintptr_t *)regs, get_curr_enclave_id());
				regs->mepc = csr_read(CSR_MEPC);
				regs->mstatus = csr_read(CSR_MSTATUS);
				regs->a0 = -1;
				return 0;
			}
			break;
	}

	spin_lock(&cpu_in_critical_lock);
	CPU_IN_CRITICAL = CPU_ENABLE_NOTIFICATION(current_hartid());
	if (((CPU_FLUSH_TAG & (1<<current_hartid())) == 1)
		&& (CPU_NEED_FLUSH[1<<current_hartid()] == 1))
	{
		__asm__ __volatile__ ("sfence.vma" : : : "memory");
		CPU_FLUSH_TAG = REMOVE_FLUSH_TAG(current_hartid());
	}
	spin_unlock(&cpu_in_critical_lock);

	regs->a0 = retval;
	if (!cpu_in_enclave(csr_read(CSR_MHARTID)))
	{
		if ((retval >= 0UL) && (retval <= SBI_LEGAL_MAX))
		{
			regs->a0 = SBI_OK;
			regs->a1 = retval;
		}
	}
	regs->mepc = csr_read(CSR_MEPC);
	regs->mstatus = csr_read(CSR_MSTATUS);
	return 0;
}

int sbi_ecall_handler(struct sbi_trap_regs *regs)
{
	int ret = 0;
	struct sbi_ecall_extension *ext;
	unsigned long extension_id = regs->a7;
	unsigned long func_id = regs->a6;
	struct sbi_trap_info trap = {0};
	unsigned long out_val = 0;
	bool is_0_1_spec = 0;
	unsigned long args[6];

	args[0] = regs->a0;
	args[1] = regs->a1;
	args[2] = regs->a2;
	args[3] = regs->a3;
	args[4] = regs->a4;
	args[5] = regs->a5;
	// sbi_printf("SBI ECALL extension_id is %lx func_id is %lx\n", extension_id, func_id);
	ext = sbi_ecall_find_extension(extension_id);
	if (extension_id != SBI_EXT_PENGLAI_HOST)
	{
		if (ext && ext->handle) {
			ret = ext->handle(extension_id, func_id,
					args, &out_val, &trap);
			if (extension_id >= SBI_EXT_0_1_SET_TIMER &&
				extension_id <= SBI_EXT_0_1_SHUTDOWN)
				is_0_1_spec = 1;
		} else {
			ret = SBI_ENOTSUPP;
		}
	}
	else
	{
		spin_lock(&cpu_in_critical_lock);
		CPU_IN_CRITICAL = REMOVE_CPU_FROM_NOTIFICATION(current_hartid());
		spin_unlock(&cpu_in_critical_lock);
		ret = ext->handle(extension_id, func_id,
					(unsigned long *)regs, &out_val, &trap);
		spin_lock(&cpu_in_critical_lock);
		CPU_IN_CRITICAL = CPU_ENABLE_NOTIFICATION(current_hartid());
		if (((CPU_FLUSH_TAG & (1<<current_hartid())) == 1)
		&& (CPU_NEED_FLUSH[1<<current_hartid()] == 1))
		{
			__asm__ __volatile__ ("sfence.vma" : : : "memory");
			CPU_FLUSH_TAG = REMOVE_FLUSH_TAG(current_hartid());
		}
		spin_unlock(&cpu_in_critical_lock);
	}


	if ((ret == SBI_ETRAP) && (extension_id != SBI_EXT_PENGLAI_HOST)) {
		trap.epc = regs->mepc;
		sbi_trap_redirect(regs, &trap);
	} else {
		if ((ret < SBI_LAST_ERR) && (extension_id != SBI_EXT_PENGLAI_HOST)) {
			sbi_printf("%s: Invalid error %d for ext=0x%lx "
				   "func=0x%lx\n", __func__, ret,
				   extension_id, func_id);
			ret = SBI_ERR_FAILED;
		}

		/*
		 * This function should return non-zero value only in case of
		 * fatal error. However, there is no good way to distinguish
		 * between a fatal and non-fatal errors yet. That's why we treat
		 * every return value except ETRAP as non-fatal and just return
		 * accordingly for now. Once fatal errors are defined, that
		 * case should be handled differently.
		 */
		if (extension_id != SBI_EXT_PENGLAI_HOST)
		{
			regs->mepc += 4;
			regs->a0 = ret;
			if (!is_0_1_spec)
				regs->a1 = out_val;
		}
		else
		{
			regs->a0 = out_val;
			if (!cpu_in_enclave(csr_read(CSR_MHARTID)))
			{
				if ((out_val >= 0UL) && (out_val <= SBI_LEGAL_MAX))
				{
					regs->a0 = SBI_OK;
					regs->a1 = out_val;
				}
			}
		}
	}

	return 0;
}

int sbi_ecall_init(void)
{
	int ret;

	/* The order of below registrations is performance optimized */
	ret = sbi_ecall_register_extension(&ecall_time);
	if (ret)
		return ret;
	ret = sbi_ecall_register_extension(&ecall_rfence);
	if (ret)
		return ret;
	ret = sbi_ecall_register_extension(&ecall_ipi);
	if (ret)
		return ret;
	ret = sbi_ecall_register_extension(&ecall_base);
	if (ret)
		return ret;
	ret = sbi_ecall_register_extension(&ecall_hsm);
	if (ret)
		return ret;
	ret = sbi_ecall_register_extension(&ecall_legacy);
	if (ret)
		return ret;
	ret = sbi_ecall_register_extension(&ecall_vendor);
	if (ret)
		return ret;
	ret = sbi_ecall_register_extension(&ecall_penglai);
	if (ret)
		return ret;

	return 0;
}
