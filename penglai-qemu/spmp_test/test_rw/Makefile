obj-m += test_read_write.o
linux_srcdir := $(PWD)/../../work/linux
all:
	make -C $(linux_srcdir) ARCH=riscv M=$(PWD)/test_rw modules

clean:
	make -C $(linux_srcdir) ARCH=riscv M=$(PWD)/test_rw clean
