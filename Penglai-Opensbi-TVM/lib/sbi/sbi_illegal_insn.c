/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_bitops.h>
#include <sbi/sbi_emulate_csr.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_illegal_insn.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_unpriv.h>
#include <sbi/sbi_console.h>

typedef int (*illegal_insn_func)(ulong insn, struct sbi_trap_regs *regs);

static int truly_illegal_insn(ulong insn, struct sbi_trap_regs *regs)
{
	struct sbi_trap_info trap;

	trap.epc = regs->mepc;
	trap.cause = CAUSE_ILLEGAL_INSTRUCTION;
	trap.tval = insn;
	trap.tval2 = 0;
	trap.tinst = 0;

	return sbi_trap_redirect(regs, &trap);
}

static int system_opcode_insn(ulong insn, struct sbi_trap_regs *regs)
{
	int do_write, rs1_num = (insn >> 15) & 0x1f;
	ulong rs1_val = GET_RS1(insn, regs);
	int csr_num   = (u32)insn >> 20;
	ulong csr_val, new_csr_val;

	/* TODO: Ensure that we got CSR read/write instruction */

	if (sbi_emulate_csr_read(csr_num, regs, &csr_val))
		return truly_illegal_insn(insn, regs);

	do_write = rs1_num;
	switch (GET_RM(insn)) {
	case 1:
		new_csr_val = rs1_val;
		do_write    = 1;
		break;
	case 2:
		new_csr_val = csr_val | rs1_val;
		break;
	case 3:
		new_csr_val = csr_val & ~rs1_val;
		break;
	case 5:
		new_csr_val = rs1_num;
		do_write    = 1;
		break;
	case 6:
		new_csr_val = csr_val | rs1_num;
		break;
	case 7:
		new_csr_val = csr_val & ~rs1_num;
		break;
	default:
		return truly_illegal_insn(insn, regs);
	};

	if (do_write && sbi_emulate_csr_write(csr_num, regs, new_csr_val))
		return truly_illegal_insn(insn, regs);

	SET_RD(insn, regs, csr_val);

	regs->mepc += 4;

	return 0;
}

static illegal_insn_func illegal_insn_table[32] = {
	truly_illegal_insn, /* 0 */
	truly_illegal_insn, /* 1 */
	truly_illegal_insn, /* 2 */
	truly_illegal_insn, /* 3 */
	truly_illegal_insn, /* 4 */
	truly_illegal_insn, /* 5 */
	truly_illegal_insn, /* 6 */
	truly_illegal_insn, /* 7 */
	truly_illegal_insn, /* 8 */
	truly_illegal_insn, /* 9 */
	truly_illegal_insn, /* 10 */
	truly_illegal_insn, /* 11 */
	truly_illegal_insn, /* 12 */
	truly_illegal_insn, /* 13 */
	truly_illegal_insn, /* 14 */
	truly_illegal_insn, /* 15 */
	truly_illegal_insn, /* 16 */
	truly_illegal_insn, /* 17 */
	truly_illegal_insn, /* 18 */
	truly_illegal_insn, /* 19 */
	truly_illegal_insn, /* 20 */
	truly_illegal_insn, /* 21 */
	truly_illegal_insn, /* 22 */
	truly_illegal_insn, /* 23 */
	truly_illegal_insn, /* 24 */
	truly_illegal_insn, /* 25 */
	truly_illegal_insn, /* 26 */
	truly_illegal_insn, /* 27 */
	system_opcode_insn, /* 28 */
	truly_illegal_insn, /* 29 */
	truly_illegal_insn, /* 30 */
	truly_illegal_insn  /* 31 */
};


extern uintptr_t pt_area_base;
extern uintptr_t pt_area_size;
extern uintptr_t mbitmap_base;
extern uintptr_t mbitmap_size;
extern uintptr_t pgd_order;
extern uintptr_t pmd_order;

int sbi_illegal_insn_handler(ulong insn, struct sbi_trap_regs *regs)
{
	struct sbi_trap_info uptrap;
	struct sbi_trap_info uptrap2;
	ulong inst;
	if (insn == 0)
		inst = sbi_get_insn(regs->mepc, &uptrap2);
	else
		inst = insn;
	
	// Emulate the TVM
	unsigned long mepc = regs->mepc;
	/* Case1: write sptbr trapped by TVM */
	if ((((inst>>20) & 0xfff) == 0x180)
		&&((inst & 0x7f) == 0b1110011)
		&& (((inst>>12) & 0x3) == 0b001))
	{
		// printm("here0 %d\r\n",((inst>>15) & 0x1f));
		unsigned long val = *((unsigned long *)regs + ((inst>>15) & 0x1f));
		unsigned long pa = (val & 0x3fffff)<<12;
		bool enable_mmu = ((val >> 60) == 0x8);
		if((pt_area_base < pa) && ((pt_area_base + (1<<pgd_order)*4096) > pa) && enable_mmu)
		{
			asm volatile ("csrrw x0, sptbr, %0":: "rK"(val));
			csr_write(CSR_MEPC, mepc + 4);
			regs->mepc = csr_read(CSR_MEPC);
			return 0 ;
		}
	}
	/* Case2: read sptbr trapped by TVM */
	if((((inst>>20) & 0xfff) == 0x180)
	&&((inst & 0x7f) == 0b1110011)
	&& (((inst>>12) & 0x3) == 0b010))
	{
		// printm("here3 %d\r\n",((inst>>7) & 0x1f));
		int idx = ((inst>>7) & 0x1f);
		unsigned long __tmp;
		asm volatile ("csrrs %0, sptbr, x0":"=r"(__tmp));
		csr_write(CSR_MEPC, mepc + 4);
		*((unsigned long *)regs + idx) = __tmp;
		regs->mepc = csr_read(CSR_MEPC);
		return 0 ;
	}
	/* Case3: sfence.vma trapped by TVM */
	if((((inst>>25) & 0x7f) == 0b0001001)
	&&((inst & 0x7fff) == 0b1110011))
	{
		// printm("here5 %d\r\n",((inst>>7) & 0x1f));
		asm volatile ("sfence.vma");
		csr_write(CSR_MEPC, mepc + 4);
		regs->mepc = csr_read(CSR_MEPC);
		return 0 ;
	}
	// End of the TVM trap handler 

	if (unlikely((insn & 3) != 3)) {
		if (insn == 0) {
			insn = sbi_get_insn(regs->mepc, &uptrap);
			if (uptrap.cause) {
				uptrap.epc = regs->mepc;
				return sbi_trap_redirect(regs, &uptrap);
			}
		}
		if ((insn & 3) != 3)
			return truly_illegal_insn(insn, regs);
	}

	return illegal_insn_table[(insn & 0x7c) >> 2](insn, regs);
}
