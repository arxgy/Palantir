CC	= $(MULTILIB_TOOLCHAIN)riscv64-unknown-linux-gnu-gcc
LINK	= $(MULTILIB_TOOLCHAIN)riscv64-unknown-linux-gnu-ld
AS	= $(MULTILIB_TOOLCHAIN)riscv64-unknown-linux-gnu-as
CFLAGS += -Wall -g

SDK_LIB_DIR = $(PENGLAI_SDK)/lib
MUSL_LIB_DIR = $(PENGLAI_SDK)/musl/lib
MUSL_LIBC = $(MUSL_LIB_DIR)/libc.a
SDK_APP_LIB = $(SDK_LIB_DIR)/libpenglai-enclave-eapp.a
#GCC_LIB = $(SDK_LIB_DIR)/libgcc.a
GCC_LIB = $(MULTILIB_TOOLCHAIN)/../lib/gcc/riscv64-unknown-linux-gnu/9.2.0/lib64/lp64/libgcc.a
SDK_INCLUDE_DIR = $(SDK_LIB_DIR)/app/include

# Library and include files for wolfssl
WOLFSSL_LIB_DIR = $(PENGLAI_SDK)/lib
WOLFSSL_INCLUDE_DIR = $(PENGLAI_SDK)/lib/wolfssl
WOLFSSL_LIB = $(WOLFSSL_LIB_DIR)/libwolfcrypt.a

# Library and include files for mbedtls
MBEDTLS_INCLUDE_DIR = $(PENGLAI_SDK)/lib/mbedtls/include
MBEDTLS_LIB = $(PENGLAI_SDK)/lib/mbedtls/library/libmbedcrypto.a

LDFLAGS += -static -L$(SDK_LIB_DIR) -L$(MUSL_LIB_DIR) -lc -lm
#LDFLAGS = -static -L$(SDK_LIB_DIR) -lpenglai-enclave-eapp
CFLAGS += -I$(SDK_INCLUDE_DIR) -I$(WOLFSSL_INCLUDE_DIR) -I$(MBEDTLS_INCLUDE_DIR) -mabi=lp64 -march=rv64imac

APP_C_OBJS = $(patsubst %.c,%.o, $(APP_C_SRCS))
APP_A_OBJS = $(patsubst %.s,%.o, $(APP_A_SRCS))
APP_LDS ?= $(PENGLAI_SDK)/app.lds

APP_BIN = $(patsubst %,%,$(APP))

all: $(APP_BIN)

$(APP_C_OBJS): %.o: %.c
	echo $(PENGLAI_SDK)
	$(CC) $(CFLAGS) -c $<

$(APP_BIN): % : $(APP_C_OBJS) $(APP_A_OBJS) $(SDK_APP_LIB) $(WOLFSSL_LIB) $(MBEDTLS_LIB) $(MUSL_LIBC) $(GCC_LIB)
	$(LINK) $(LDFLAGS) -o $@ $^ -T $(APP_LDS)
	chmod -x $@

clean:
	rm -f *.o $(APP_BIN) $(EXTRA_CLEAN)
