CC=gcc
CFLAGS=-I ../src -Wall -O3
SRC=../src

LIBESTREAM_OBJS=$(patsubst %, $(SRC)/%, grain.o hc128.o mickey.o rabbit.o salsa.o sosemanuk.o trivium.o)
ESTREAM_OBJS=estream.o

LIBESTREAM=libestream.so
ESTREAM=estream

all: $(LIBESTREAM) $(ESTREAM)

.c.o:
	$(CC) $(CFLAGS) -fPIC -c $^ -o $@

$(LIBESTREAM): $(LIBESTREAM_OBJS)
	$(CC) $(CFLAGS) -shared -o $@ $^
	rm -f $(SRC)/*.o

$(ESTREAM): $(ESTREAM_OBJS)
	$(CC) $(CFALGS) -L./ -lestream -Wl,-rpath,. -o $@ $^

clean:
	rm -f $(SRC)/*.o *.o $(LIBESTREAM) $(ESTREAM)
