all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C fork-host
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C eval-2-interface
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-measure
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C rv8-baseline
	make -C hello-world
	make -C relay-page
	make -C mem
	make -C eval-1-benchmark
	make -C IPC
	make -C FS
	make -C test-stop
	make -C psa
	make -C seperated_filesystem_simple
	make -C case-1-introspection
	make -C case-2-sharing
	make -C case-3-migration

	#CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  mphost_normal

clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-measure clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C eval-2-interface clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C fork-host clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C rv8-baseline clean
	make -C hello-world clean
	make -C relay-page clean
	make -C mem clean
	make -C eval-1-benchmark clean
	make -C IPC clean
	make -C FS clean
	make -C test-stop clean
	make -C psa clean
	make -C seperated_filesystem_simple clean
	make -C case-1-introspection clean
	make -C case-2-sharing clean
	make -C case-3-migration clean

