CC=gcc
CFLAGS=-I ../lib -Wall -O3
LIB=../lib

LIBESTREAM_OBJS=$(patsubst %, $(LIB)/%, grain.o hc128.o mickey.o rabbit.o salsa.o sosemanuk.o trivium.o gost89.o)
ESTREAM_OBJS=estream.o

LIBESTREAM=libestream.so
ESTREAM=estream

all: $(LIBESTREAM) $(ESTREAM)

.c.o:
	$(CC) $(CFLAGS) -fPIC -c $^ -o $@

$(LIBESTREAM): $(LIBESTREAM_OBJS)
	$(CC) $(CFLAGS) -shared -o $@ $^
	rm -f $(LIB)/*.o

$(ESTREAM): $(ESTREAM_OBJS)
	$(CC) $(CFALGS) -L./ -lestream -Wl,-rpath,. -o $@ $^

clean:
	rm -f $(LIB)/*.o *.o $(LIBESTREAM) $(ESTREAM)
