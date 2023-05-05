all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C app
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C wolfssl
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C mbedtls lib

clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C app clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C wolfssl clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C mbedtls clean
