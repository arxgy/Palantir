HOST=sha512-baseline

all:
	$(CC) -static -mabi=lp64  -march=rv64imac  -o $(HOST)   sha512.c 
clean:
	rm -f *.o $(HOST)
