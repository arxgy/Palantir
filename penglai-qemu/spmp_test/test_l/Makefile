obj-m += test_l_bit.o
linux_srcdir := $(PWD)/../../work/linux
all:
	make -C $(linux_srcdir) ARCH=riscv M=$(PWD)/test_l modules

clean:
	make -C $(linux_srcdir) ARCH=riscv M=$(PWD)/test_l clean
