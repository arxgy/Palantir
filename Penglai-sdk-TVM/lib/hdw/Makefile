CFLAGS = -Wall -mabi=lp64 -march=rv64imac
CFLAGS += -I.
CFLAGS += -DVALGRIND=$(VALGRIND)
CFLAGS += -DUSE_ETHEREUM=0
CFLAGS += -DUSE_GRAPHENE=1
CFLAGS += -DUSE_KECCAK=1
CFLAGS += -DUSE_MONERO=0
CFLAGS += -DUSE_NEM=1
CFLAGS += -DUSE_CARDANO=1

ARFLAGS = rcs

# CFLAGS += $(shell pkg-config --cflags openssl)
TARGET = ../libhdw.a

# disable certain optimizations and features when small footprint is required
ifdef SMALL
CFLAGS += -DUSE_PRECOMPUTED_CP=0
endif


SRC_DIRS = aes_coin ed25519-donna
SRC  = $(wildcard $(addsuffix /*.c, $(SRC_DIRS)))
SRC += $(wildcard *.c)
OBJ = $(SRC:.c=.o)

all: $(TARGET)


# Create the static library
$(TARGET): $(OBJ)
	$(AR) $(ARFLAGS) $@ $(OBJ)

# Compile each .c file into a .o file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJ) $(TARGET)

# Rebuild the library from scratch
rebuild: clean all

.PHONY: all clean rebuild
