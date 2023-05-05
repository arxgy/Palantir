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
 * S-mode can not excute code in user memory.
 * spmp1cfg = 0b01011111 -> 0x5f
 * Code injection: 0x0e900893 -> li a7, 233
 * Little-endian -> 0x9308900e
 */
static void test_smep(uintptr_t spmpcfg, uintptr_t spmpaddr, uintptr_t paddr)
{
	printk("[SMEP]\n");
	printk("[TEST] S-mode can not excute code in user memory.\n");
	printk("[TEST] With U-bit been set.\n");

	/* Code injction */
	char(*code_addr)[1024] = (char(*)[1024])map_pa_to_va(paddr);
	**code_addr = 0x9308900e;

	/* Set sPMP */
	csr_write(0x1a0, _VAL(spmpcfg));
	csr_write(0x1b0, _VAL(spmpaddr));

	/* Attempt to execute */
	void(*f)(void) = map_pa_to_va(paddr);
	printk("[TEST] kernel will panic!\n");
	f();

	printk("[SMEP TEST FAIL] kernel haven't panic\n");
}

static int test_init(void)
{
	test_smep(0x5f, 0x208ccdff, 0x82333000);

	return 0;
}

static void test_exit(void)
{
	printk("module removed\n");
}

module_init(test_init);
module_exit(test_exit);

