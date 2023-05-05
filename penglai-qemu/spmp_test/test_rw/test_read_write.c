#include <linux/kernel.h>
#include <linux/module.h>
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
 * Write\read test
 * spmp0cfg = 0b00001111 -> 0x0f
 * Please check Proposal of sPMP 
 * for configuration of spmpcfg register.
 */
static void test_read_write(uintptr_t spmpcfg, uintptr_t spmpaddr0)
{
	printk("[START] start sPMP read/write test\n");

	csr_write(0x1b0, _VAL(spmpaddr0));
	csr_write(0x1a0, _VAL(spmpcfg));
	uintptr_t cfg = csr_read(0x1a0);
	uintptr_t addr0 = csr_read(0x1b0);

	printk("[TEST] spmpcfg0 = 0x%lx\n", cfg);
	printk("[TEST] spmpaddr0 = 0x%lx\n", addr0);

	if ((cfg == spmpcfg) && (addr0 == spmpaddr0))
	{
		printk("[OK]\n");
	} else {
		printk("[READ/WRITE TEST FAIL]\n");
	}
}

static int test_init(void)
{
	test_read_write(0x0f, 0x2200000000);

	return 0;
}

static void test_exit(void)
{
	printk("module removed\n");
}

module_init(test_init);
module_exit(test_exit);

