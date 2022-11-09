TEST=test
all_x86:
	gcc test.c -o $(TEST)

clean_x86:
	rm *.o test


CC = /home/penglai/penglai-multilib-toolchain-install/bin/riscv64-unknown-linux-gnu-gcc

all_penglai:
	$(CC) -static -mabi=lp64  -march=rv64imac  -o $(TEST)  test.c

