HOST=host-hdw

all:
	$(CC) -static -mabi=lp64  -march=rv64imac  -o $(HOST) -I $(PENGLAI_SDK)/lib/host/include/ -I $(PENGLAI_SDK)/lib/hdw  host-hdw.c  $(PENGLAI_SDK)/lib/libpenglai-enclave-host.a $(PENGLAI_SDK)/lib/libhdw.a  -lpthread
# $(CC) -static -mabi=lp64  -march=rv64imac  -o $(HOST) -I $(PENGLAI_SDK)/lib/host/include/ host-hdw.c  $(PENGLAI_SDK)/lib/libpenglai-enclave-host.a -lpthread

clean:
	rm -f *.o $(HOST)
