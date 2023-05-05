obj-m += test_smap.o
linux_srcdir := $(PWD)/../../work/linux
all:
	make -C $(linux_srcdir) ARCH=riscv M=$(PWD)/test_smap modules

clean:
	make -C $(linux_srcdir) ARCH=riscv M=$(PWD)/test_smap clean
