# pass the signature verification
CONFIG_MODULE_SIG=n

obj-m += ext.o

ext-objs := ext-driver.o \
				 ext-ioctl.o  \
				 ext-sbi.o  \

HOST_LINUX_SRC := /lib/modules/$(shell uname -r)/build
PENGLAI_LINUX_SRC := ../../work/linux-5.10.2/
KEYSTONE_LINUX_SRC := ../../../keystone/linux
# host
host:
	make -C $(HOST_LINUX_SRC) M=$(PWD) modules

# clean_x86:
# 	make -C $(HOST_LINUX_SRC) M=$(PWD) clean

# penglai platform: in the docker
penglai:
	make -C $(PENGLAI_LINUX_SRC) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- M=$(PWD) modules

# # clean_penglai:
# # 	make -C $(PENGLAI_LINUX_SRC) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- M=$(PWD) clean

# # keystone platform
# keystone: 
# 	make -C $(KEYSTONE_LINUX_SRC) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- M=$(PWD) modules

clean:
	rm -rvf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*.cmd
