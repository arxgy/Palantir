CFLAGS = -Wall -mabi=lp64 -march=rv64imac
LINKFLAGS = -static
INCLUDE_DIR = .
ARFLAGS = rcs
SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
TARGET = ../libwolfcrypt.a

all: $(TARGET)


$(OBJS): %.o:%.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@ -DWOLFCRYPT_ONLY -DNO_ASN -DWOLFSSL_KEY_GEN -DSINGLE_THREADED -DPENGLAI -DHAVE_AESGCM


$(TARGET): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f $(OBJS) $(TARGET)

# all:
# 	$(CC) -static -mabi=lp64  -march=rv64imac  -o test_crypto   $(SRCS)  -I $(PENGLAI_SDK)/demo  -lm -DWOLFCRYPT_ONLY -DNO_ASN -DWOLFSSL_KEY_GEN -DSINGLE_THREADED
# clean:
# 	rm -f *.o test_crypto