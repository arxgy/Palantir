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

/*
 * Take a paddr, 
 * map that page in kernel, 
 * then return its vaddr.
 */
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
 * L-bit write test
 * Write to spmpcfg and spmpaddr should be ignored
 * while L-bit been set.
 * spmp0cfg = 0b11011101 -> 0xdd
 * spmpaddr0 = 0x208ccdff
 * region0 = [0x82333000, 0x82334000)
 */
static void test_l_bit_write(uintptr_t spmpcfg, uintptr_t spmpaddr)
{
	/* Initial set up */
	csr_write(0x1b0, _VAL(spmpaddr));
	csr_write(0x1a0, _VAL(spmpcfg));
	printk("[START] sPMP lock register write test\n");
	printk("[TEST] Write to spmpcfg and spmpaddr should be ignored when spmp been locked\n");
	printk("[TEST] set spmpcfg0 to 0x%lx\n", spmpcfg);
	printk("[TEST] set spmpaddr0 to 0x%lx\n", spmpaddr);
	printk("[TEST] spmp0 is now LOCKED\n");

	/* Try to write spmpaddr and spmpcfg */
	printk("[TEST] write 0x12345678 to spmpsddr0\n");
	printk("[TEST] write 0x1f to spmpcfg0\n");
	csr_write(0x1b0, 0x12345678);
	csr_write(0x1a0, 0x1f);

	/* Check the result */
	uintptr_t cfg = csr_read(0x1a0);
	uintptr_t addr = csr_read(0x1b0);
	printk("[TEST] spmpcfg0 = 0x%lx\n", cfg); 
	printk("[TEST] spmpaddr0 = 0x%lx\n", addr); 

	if ((cfg == spmpcfg) && (addr == spmpaddr))
	{
		printk("[TEST] S-mode write is IGNORED\n");
		printk("[OK]\n");
	} else {
		printk("[L-BIT WRITE TEST FAIL]\n");
	}
}

/*
 * R/W/X permissions should apply to S-mode 
 * while L-bit been set.
 * spmp0cfg = 0b10011101 -> 0x9d
 * spmpaddr0 = 0x208ccdff
 * region0 = [0x82333000, 0x82334000)
 */
static void test_l_bit_access(uintptr_t paddr)
{
	printk("[START] sPMP lock S-mode unpermitted memory access test");
	printk("[TEST] R/W/X permissions should apply to S-mode while L-bit been set\n");
	printk("[TEST] Write permissionn in region0 is denied\n");
	
	int* addr = map_pa_to_va(paddr);
	printk("[TEST] old val of 0x%lx is %d\n", addr, *addr);
	printk("[TEST] write 42 to 0x%lx in region0\n", addr);
	printk("[TEST] kernel will panic!\n");
	*addr = 42;

	printk("[L-BIT ACCESS TEST FAIL] kernel haven't panic with unpermitted write\n");
}

static int test_init(void)
{
	test_l_bit_write(0x9d, 0x208ccdff);
	test_l_bit_access(0x82333000);

	return 0;
}

static void test_exit(void)
{
	printk("module removed\n");
}

module_init(test_init);
module_exit(test_exit);

