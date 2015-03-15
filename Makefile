CC=gcc
CFLAGS=-Wall -O3 -fPIC
CFLAGS_SO=-Wall -O3 -shared
LIB=./lib

LIBESTREAM_OBJS=$(LIB)/estream.o
LIBESTREAM=libestream.so

all: $(LIBESTREAM)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@

$(LIBESTREAM): $(LIBESTREAM_OBJS)
	$(CC) $(CFLAGS_SO) -o $@ $^

clean:
	rm -f *.o $(LIB)/*.o $(LIBESTREAM)
