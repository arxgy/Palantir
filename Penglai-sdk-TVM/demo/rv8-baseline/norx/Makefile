HOST=norx-baseline


all:
	$(CC) -static -mabi=lp64  -march=rv64imac  -o $(HOST) norx.c  

clean:
	rm -f *.o $(HOST)
