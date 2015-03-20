CC=gcc
CFLAGS=-Wall -O3 -fPIC
CFLAGS_SO=-Wall -O3 -shared
SRC=../src

LIBESTREAM_OBJS=$(patsubst %, $(SRC)/%, grain.o hc128.o mickey.o rabbit.o salsa.o sosemanuk.o trivium.o)
ESTREAM_SPEED_TEST_OBJS=estream_speed_test.o

LIBESTREAM=libestream.so
ESTREAM_SPEED_TEST=estream_speed_test

all: $(LIBESTREAM) $(ESTREAM_SPEED_TEST)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@ 

$(LIBESTREAM): $(LIBESTREAM_OBJS)
	$(CC) $(CFLAGS_SO) -o $@ $^

$(ESTREAM_SPEED_TEST): $(ESTREAM_SPEED_TEST_OBJS)
	$(CC) -Wall -O3 -L./ -lestream -o $@ $^

clean:
	rm -f $(SRC)/*.o *.o $(LIBESTREAM)
