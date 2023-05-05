all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_client
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_crypto
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_key_ladder
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_server
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_host
	# CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_key
clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_client clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_crypto clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_key_ladder clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_server clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_host clean
	# CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  psa_key clean