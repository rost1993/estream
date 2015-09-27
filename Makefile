CC=gcc
CFLAGS=-I ./lib -I ./lib/hash -Wall -O3
CFLAGS_HASH=-I ./lib/hash -Wall -O2
LIB=./lib
HASH=./lib/hash

LIBESTREAM_OBJS=$(patsubst %, $(LIB)/%, grain.o hc128.o rabbit.o salsa.o sosemanuk.o trivium.o mickey.o)
LIBHASH_OBJS=$(patsubst %, $(HASH)/%, md5.o sha1.o sha224.o sha256.o sha384.o sha512.o sha3.o)

LIBESTREAM=libestream.so
LIBHASH=libhash.so

all: $(LIBESTREAM)

.c.o:
	$(CC) $(CFLAGS) -fPIC -c $^ -o $@

$(LIBESTREAM): $(LIBESTREAM_OBJS) $(LIBHASH_OBJS)
	$(CC) $(CFLAGS) -shared -o $@ $^
	rm -f $(SRC)/*.o

$(LIBHASH): $(LIBHASH_OBJS)
	$(CC) $(CFLAGS_HASH) -shared -o $@ $^
	rm -f $(HASH)/*.o

clean:
	rm -f $(LIB)/*.o $(LIBESTREAM)
	rm -f $(HASH)/*.o $(LIBHASH)
