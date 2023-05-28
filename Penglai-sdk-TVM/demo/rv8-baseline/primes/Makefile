HOST=primes-baseline


all:
	$(CC) -static -mabi=lp64  -march=rv64imac -I $(PENGLAI_SDK)/lib/host/include/ -o $(HOST)   primes.c  -lm

clean:
	rm -f *.o $(HOST)
