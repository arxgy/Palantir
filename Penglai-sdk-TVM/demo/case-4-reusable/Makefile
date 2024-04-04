all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-attestation
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-payload
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-reset
clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-attestation clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-payload clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-reset clean