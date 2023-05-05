obj-m += test_smep.o
linux_srcdir := $(PWD)/../../work/linux
all:
	make -C $(linux_srcdir) ARCH=riscv M=$(PWD)/test_smep modules

clean:
	make -C $(linux_srcdir) ARCH=riscv M=$(PWD)/test_smep clean
