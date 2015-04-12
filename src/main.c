#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <unistd.h>
#include <malloc.h>

#include <sys/mman.h>

#include "estream.h"

#define PAGE_ADDR(p, pgsize)	(p - PAGE_ALIGN(p, pgsize))
#define PAGE_ALIGN(p, pgsize)	((long )p % pgsize)

int
universe(void)
{
	return 42;
}

void
universe_stop(void) {};

static void
help(void)
{
	printf("Program works!\n");
}

int
main(int argc, char *argv[])
{
	struct salsa_context ctx;
	char k[256];
	uint8_t key[32], iv[8];
	int res, funcsz, pagesize, keylen = 0;
	uint8_t *buf;
	int (*func)(void);

	const struct option long_option [] = {
		{"help", 0, NULL, 'h'},
		{"key",  1, NULL, 'k'},
		{0,      0, NULL,  0 }
	};

	if(argc < 2) {
		help();
		return 0;
	}

	while((res = getopt_long(argc, argv, "k:t:h", long_option, 0)) != -1) {
		switch(res) {
		case 'h' : help();
		   	   return 0;
		case 'k' : strcpy(k, optarg);
		   	   keylen = strlen(k);
		   	   break;
		}
	}
	
	// Get key and IV
	memset(iv, 0, sizeof(iv));
	
	if(keylen > 32)
		keylen = 32;
	
	memcpy(key, k, keylen);

	salsa_init(&ctx);

	if(salsa_set_key_and_iv(&ctx, key, keylen, iv, 8)) {
		printf("Filling salsa context error!\n");
		exit(1);
	}

	pagesize = sysconf(_SC_PAGE_SIZE);
	funcsz = (void *)universe_stop - (void *)universe;

	if((buf = malloc(PAGE_ALIGN(universe, pagesize) + funcsz)) == NULL) {
		printf("Allocates memory error!\n");
		exit(1);
	}

	memcpy(buf, universe, funcsz);

	if(mprotect(PAGE_ADDR(buf, pagesize), PAGE_ALIGN(buf, pagesize) + funcsz, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
		printf("Mprotect error!\n");
		exit(1);
	}

	salsa_encrypt(&ctx, buf, PAGE_ALIGN(buf, pagesize) + funcsz, buf);

	func = (void *)buf;
	printf("Result = %d\n", func());

	free(buf);
		
	return 0;
}

