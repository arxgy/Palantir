all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-root
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-raw-wallet
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-raw-speed
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-wallet-child1
clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-root clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-raw-wallet clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-raw-speed clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-wallet-child1 clean