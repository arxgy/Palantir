HOST=qsort-baseline


all:
	$(CC) -static -mabi=lp64  -march=rv64imac  -o $(HOST)   qsort.c 

clean:
	rm -f *.o $(HOST)
