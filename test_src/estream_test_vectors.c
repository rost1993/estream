/*
 * This program tests the algorithms eSTREAM project to test vector perfomance
 * Makefile: Makefile_test_vectors
 * Compile: make -f Makefile_test_vectors
 * Example: ./estream_test_vectors -h ./estream_test_vectors -a 1
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include "estream.h"

// Secret key
uint8_t key[32] = { 0x00, 0x11, 0x22, 0x33,
		    0x44, 0x55, 0x66, 0x77,
		    0x88, 0x99, 0xAA, 0xBB,
		    0xCC, 0xDD, 0xEE, 0xFF,
		    0x00, 0x11, 0x22, 0x33,
		    0x44, 0x55, 0x66, 0x77,
		    0x88, 0x99, 0xAA, 0xBB,
		    0xCC, 0xDD, 0xEE, 0xFF };

// Vector initialization
uint8_t iv[16] = { 0x01, 0x23, 0x45, 0x67,
		   0x89, 0xAB, 0xCD, 0xEF,
		   0x01, 0x23, 0x45, 0x67,
		   0x89, 0xAB, 0xCD, 0xEF };

// Interface to the library salsa.h
static void
salsa(void)
{
	struct salsa_context ctx;

	salsa_init(&ctx);

	if(salsa_set_key_and_iv(&ctx, key, 32, iv, 8)) {
		printf("Salsa context filling error!\n");
		exit(1);
	}

	salsa_test_vectors(&ctx);
}

// Interface to the library rabbit.h
static void
rabbit(void)
{
	struct rabbit_context ctx;
	
	rabbit_init(&ctx);

	if(rabbit_set_key_and_iv(&ctx, key, 16, iv, 8)) {
		printf("Rabbit context filling error!\n");
		exit(1);
	}

	rabbit_test_vectors(&ctx);
}

// Interface to the hc128.h
static void
hc128(void)
{
	struct hc128_context ctx;

	hc128_init(&ctx);

	if(hc128_set_key_and_iv(&ctx, key, 16, iv, 16)) {
		printf("HC128 context filling error!\n");
		exit(1);
	}

	hc128_test_vectors(&ctx);
}

// Interface to the library sosemanuk.h
static void
sosemanuk(void)
{
	struct sosemanuk_context ctx;

	sosemanuk_init(&ctx);

	if(sosemanuk_set_key_and_iv(&ctx, key, 32, iv, 16)) {
		printf("Sosemanuk context filling error!\n");
		exit(1);
	}

	sosemanuk_test_vectors(&ctx);
}

// Interface to the library grain.h
static void
grain(void)
{
	struct grain_context ctx;

	grain_init(&ctx);

	if(grain_set_key_and_iv(&ctx, key, 16, iv, 12)) {
		printf("Grain context filling error!\n");
		exit(1);
	}

	grain_test_vectors(&ctx);
}

// Interface to the library mickey.h
static void
mickey(void)
{
	struct mickey_context ctx;

	mickey_init(&ctx);

	if(mickey_set_key_and_iv(&ctx, key, 10, iv, 10)) {
		printf("Mickey context filling error!\n");
		exit(1);
	}
	
	mickey_test_vectors(&ctx);
}

// Interface to the library trivium.h
static void
trivium(void)
{
	struct trivium_context ctx;

	trivium_init(&ctx);

	if(trivium_set_key_and_iv(&ctx, key, 10, iv, 10)) {
		printf("Trivium context filling error!\n");
		exit(1);
	}

	trivium_test_vectors(&ctx);
}

// Manual
static void
help(void)
{
	printf("\nThis program provides the user interface for testing algorithms project eSTREAM on test vectors!\n");
	printf("\nOptions:\n");
	printf("\t--help(-h) - reference manual\n");
	printf("\t--algorithm(-a) - selection algorithm:\n");
	printf("\t\t1 - Salsa\n\t\t2 - Rabbit\n\t\t3 - HC128\n\t\t4 - Sosemanuk\n");
	printf("\t\t5 - Grain\n\t\t6 - Mickey\n\t\t7 - Trivium\n");
	printf("\nExample: ./estream_testvectors -h or ./estream_testvectors -a 1\n\n");
}

int
main(int argc, char *argv[])
{
	int res, alg = 0;

	const struct option long_option [] = {
		{"algorithm", 1, NULL, 'a'},
		{"help",      0, NULL, 'h'},
		{0,  	      0, NULL,  0 }
	};
	
	if(argc < 2) {
		help();
		return 0;
	}

	// Parse argument
	while((res = getopt_long(argc, argv, "a:h", long_option, 0)) != -1) {
		switch(res) {
		case 'h' : help();
			   return 0;
		case 'a' : alg = atoi(optarg);
			   break;
		}
	}
	
	
	switch(alg) {
	case 1 : salsa();
		 break;
	case 2 : rabbit();
		 break;
	case 3 : hc128();
		 break;
	case 4 : sosemanuk();
		 break;
	case 5 : grain();
		 break;
	case 6 : mickey();
		 break;
	case 7 : trivium();
		 break;
	}

	return 0;
}

