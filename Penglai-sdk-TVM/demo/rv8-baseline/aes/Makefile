HOST=aes-baseline


all:
	$(CC) -static -mabi=lp64  -march=rv64imac  -o $(HOST)   aes.c 

clean:
	rm -f *.o $(HOST)
