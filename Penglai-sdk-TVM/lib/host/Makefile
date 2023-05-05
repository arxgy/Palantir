#CC = riscv64-unknown-linux-gnu-gcc
#AR = riscv64-unknown-elf-ar

INCLUDE_DIR = include/
SRC_DIR = src
CCFLAGS = -Wall -Werror -mabi=lp64 -march=rv64imac -I $(INCLUDE_DIR)
SRCS = param.c penglai-enclave.c elf.c
OBJS = $(patsubst %.c,%.o,$(SRCS))
ARFLAGS = rcs

TARGET=../libpenglai-enclave-host.a

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(OBJS): %.o: $(addprefix $(SRC_DIR)/, %.c)
	$(CC) $(CCFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET) 
