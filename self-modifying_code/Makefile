CC=gcc
CFLAGS=-Wall

CRYPTOR_OBJS=cryptor.o
MAIN_OBJS=main.o
PARSER_OBJS=parser.o

CRYPTOR=cryptor
MAIN=main
PARSER=parser

all: $(CRYPTOR) $(MAIN) $(PARSER)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@

$(MAIN): $(MAIN_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(CRYPTOR): $(CRYPTOR_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(PARSER): $(PARSER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(CRYPTOR) $(MAIN) $(PARSER)
