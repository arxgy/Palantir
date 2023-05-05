all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  server
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  server1
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  caller
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  test-caller
clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  server clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  server1 clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  caller clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  test-caller clean