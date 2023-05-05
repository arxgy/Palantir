obj-m += penglai.o
penglai-objs := penglai-enclave-driver.o \
	penglai-enclave-elfloader.o \
	penglai-shm.o \
	penglai-buddy.o \
	penglai-schrodinger.o \
	penglai-enclave-page.o \
	penglai-enclave.o \
	penglai-enclave-ioctl.o \
	penglai-enclave-persistency.o \
	penglai-enclave-ocall.o \
	buddy.o

all:
	make -C ../../work/linux-5.10.2/ ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- M=$(PWD) modules

clean:
	make -C ../../work/linux-5.10.2/ ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- M=$(PWD) clean
