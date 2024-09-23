HOST=host-hdw-speed

all:
	$(CC) -static -mabi=lp64  -march=rv64imac  -o $(HOST) -I $(PENGLAI_SDK)/lib/host/include/ -I $(PENGLAI_SDK)/lib/hdw  host-hdw-speed.c  $(PENGLAI_SDK)/lib/libpenglai-enclave-host.a $(PENGLAI_SDK)/lib/libhdw.a  -lpthread

clean:
	rm -f *.o $(HOST)
