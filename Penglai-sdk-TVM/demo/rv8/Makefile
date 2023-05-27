all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  aes
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  dhrystone
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  norx
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  primes
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  qsort
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  sha512
	
clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  aes clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  dhrystone clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  norx clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  primes clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  qsort clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  sha512 clean