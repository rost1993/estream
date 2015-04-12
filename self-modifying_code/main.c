#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <sys/mman.h>

#define PAGE_ADDR(p, pgsize)	(p - PAGE_ALIGN(p, pgsize))
#define PAGE_ALIGN(p, pgsize)	((long )p % pgsize)

#define SIZE	((void *)hello_world_stop - (void *)hello_world)

asm (".string \"rost\"");

void
hello_world(void)
{
	char *s = "Hello world!\n";
	printf(s);
}

asm (".string \"rost\"");

void
hello_world_stop() {};

void
crypt(void *ptr, char x)
{
	int pagesize, funcsize;
	char *sp = ptr;

	pagesize = sysconf(_SC_PAGE_SIZE);
	funcsize = SIZE;

	if(mprotect(PAGE_ADDR(ptr, pagesize), PAGE_ALIGN(ptr, pagesize) + funcsize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
		printf("Mprotect error!\n");
		exit(1);
	}

	while(funcsize--)
		*sp++ ^= x;
	
	if(mprotect(PAGE_ADDR(ptr, pagesize), PAGE_ALIGN(ptr, pagesize) + funcsize, PROT_READ | PROT_EXEC) != 0) {
		printf("Mprotect error!\n");
		exit(1);
	}
}

// Help function
static void
help(void)
{
	printf("\nSelf-modifying code!\n");
	printf("Options:\n");
	printf("\t-k(--key) - secret key in hexadecimal format\n");
	printf("\t-h(--help) - reference manual\n\n");
	printf("Usage: ./main -k 0xCD or ./main --key 0xCD\n\n");
}

int
main(int argc, char *argv[])
{
	unsigned char key;
	int res;

	const struct option long_option [] = {
		{"help", 0, NULL, 'h'},
		{"key",  1, NULL, 'k'},
		{0, 	 0, NULL,  0 }
	};

	while((res = getopt_long(argc, argv, "k:h", long_option, 0)) != -1) {
		switch(res) {
		case 'h' : help();
			   return 0;
		case 'k' : key = strtol(optarg, NULL, 16);
			   if(errno) {
			   	printf("Argument is not number!\n");
				exit(1);
			   }
			   break;
		default: help();
			 return 0;
		}
	}

	if(argc < 2) {
		help();
		return 0;
	}

	// Encrypt function
	crypt(hello_world, key);
	
	hello_world();

	// Decrypt function
	crypt(hello_world, key);

	return 0;
}

