CC=gcc
CFLAGS=-Wall

SERVER_OBJS=server.o
CLIENT_OBJS=client.o

SERVER=server
CLIENT=client

all: $(SERVER) $(CLIENT)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@

$(SERVER): $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(CLIENT): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(SERVER) $(CLIENT)
