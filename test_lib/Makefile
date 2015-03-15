CC=gcc
CFLAGS=-Wall -O3
LIB=../lib

ESTREAM_TEST_VECTORS_OBJS=$(LIB)/estream.o estream_test_vectors.o
ESTREAM_SPEED_TEST_OBJS=$(LIB)/estream.o estream_speed_test.o

ESTREAM_TEST_VECTORS=estream_test_vectors
ESTREAM_SPEED_TEST=estream_speed_test


all: $(ESTREAM_TEST_VECTORS) $(ESTREAM_SPEED_TEST)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@

$(ESTREAM_TEST_VECTORS): $(ESTREAM_TEST_VECTORS_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(ESTREAM_SPEED_TEST): $(ESTREAM_SPEED_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(LIB)/*.o
	rm -f $(ESTREAM_TEST_VECTORS) $(ESTREAM_SPEED_TEST)
test:
	bash ./estream_testvectors -h
