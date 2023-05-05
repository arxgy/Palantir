all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  fshost
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  littlefs
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  testfs
clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  fshost clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  littlefs clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  testfs clean
