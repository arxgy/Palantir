HOST=dhrystone-baseline


all:
	$(CC) -static -mabi=lp64  -march=rv64imac  -o $(HOST)   dhrystone.c 

clean:
	rm -f *.o $(HOST)
