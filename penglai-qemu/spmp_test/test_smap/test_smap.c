#include <linux/kernel.h>
#include <linux/module.h>
#include <asm-generic/memory_model.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>
MODULE_LICENSE("GPL");

#define _VAL(x) 		x
#define csr_write(csr, val)		\
({		\
 	uintptr_t __v = (uintptr_t)(val);		\
 	asm volatile ("csrw " #csr ", %0"		\
					: : "rK" (__v)		\
					: "memory");		\
 })

#define csr_read(csr)		\
({		\
 	register uintptr_t __v;		\
 	asm volatile ("csrr %0, " #csr		\
				: "=r" (__v) :		\
				: "memory");		\
 	__v;		\
})

static void set_sstatus_sum(bool sum)
{
	uintptr_t mask, sstatus;
	sstatus = csr_read(0x100);
	if (sum) 
	{
		mask = 1 << 18;
		sstatus |= mask;
		csr_write(0x100, _VAL(sstatus));

	} else {
		mask = ~(1 << 18);
		sstatus &= mask;
		csr_write(0x100, _VAL(sstatus));
	}
}


static void* map_pa_to_va(uintptr_t paddr)
{
	uintptr_t page_number = paddr >> 12;
	uintptr_t mask = (1 << 12) - 1;
	uintptr_t page_indent = paddr & mask;

	struct page* pp = pfn_to_page(page_number);
	void* vaddr = kmap(pp) + page_indent;
	return vaddr;
}

/*
 * With U-bit been set, 
 * S-mode can only access user memory while 
 * SUM-bit in sstatus been set.
 * spmp0cfg = 0b01011111 -> 0x5f
 */
static void test_smap(uintptr_t spmpcfg, uintptr_t spmpaddr, uintptr_t paddr)
{
	csr_write(0x1a0, _VAL(spmpcfg));
	csr_write(0x1b0, _VAL(spmpaddr));
	int* addr = map_pa_to_va(paddr);

	printk("[SMAP]\n");
	printk("[TEST] set SUM in sstatus to 1\n");
	set_sstatus_sum(1);
	printk("[TEST] sstatus = 0x%lx\n", csr_read(0x100));
	printk("[TEST] val of 0x%lx in user address = %d\n", addr, *addr);
	printk("[TEST] kernel can access user memory\n");

	printk("[TEST] set SUM in sstatus to 0\n");
	set_sstatus_sum(0);
	printk("[TEST] sstatus = 0x%lx\n", csr_read(0x100));
	printk("[TEST] try to read 0x%lx\n", addr);
	printk("[TEST] kernel will panic!\n");

	printk("[TEST] val of 0x%lx in user address = %d\n", addr, *addr);
	printk("[SMAP TEST FAIL] kernel haven't panic\n");
}

static int test_init(void)
{
	test_smap(0x5f, 0x208ccdff, 0x82333000);

	return 0;
}

static void test_exit(void)
{
	printk("module removed\n");
}

module_init(test_init);
module_exit(test_exit);

