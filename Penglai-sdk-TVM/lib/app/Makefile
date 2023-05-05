#CC = riscv64-unknown-linux-gnu-gcc
#LINK = riscv64-unknown-linux-gnu-ld
#AR = riscv64-unknown-elf-ar
CFLAGS = -Wall -mabi=lp64 -march=rv64imac -g
LINKFLAGS = -static
INCLUDE_DIR = include/
ARFLAGS = rcs

ASM_SRCS = src/eret.S
C_SRCS = src/enclave.c src/attest.c src/mmap.c src/server_enclave.c src/print.c src/sbrk.c src/persistency.c src/relay_page.c src/psa_call_stub.c src/sst_secure_api.c src/psa_callee_stub.c

A_OBJS = $(patsubst %.S,%.o,$(ASM_SRCS))
C_OBJS = $(patsubst %.c,%.o,$(C_SRCS))

TARGET = ../libpenglai-enclave-eapp.a

all: $(TARGET)

$(A_OBJS): %.o : %.S
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@
$(C_OBJS): %.o: %.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@
$(TARGET): $(A_OBJS) $(C_OBJS)
	$(AR) $(ARFLAGS) $@ $^


clean:
	rm -f $(A_OBJS) $(C_OBJS) $(TARGET)
