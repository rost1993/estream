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

// Manual
static void
help(void)
{
	printf("\nThis program provides the user interface for testing algorithms project eSTREAM on test vectors!\n");
	printf("\nOptions:\n");
	printf("\t--help(-h) - reference manual\n");
	printf("\t--algorithm(-a) - selection algorithm:\n");
	printf("\t\t0 - Salsa\n\t\t1 - Rabbit\n\t\t2 - HC128\n\t\t3 - Sosemanuk\n");
	printf("\t\t4 - Grain\n\t\t5 - Mickey\n\t\t6 - Trivium\n");
	printf("\nExample: ./estream_testvectors -h or ./estream_testvectors -a 1\n\n");
}

// Union all structures eSTREAM project
union context {
	struct salsa_context salsa;
	struct rabbit_context rabbit;
	struct hc128_context hc128;
	struct sosemanuk_context sosemanuk;
	struct grain_context grain;
	struct mickey_context mickey;
	struct trivium_context trivium;
};

typedef int (*set_t)(void *ctx, uint8_t *key, int keylen, uint8_t *iv, int ivlen);
typedef void (*test_t)(void *ctx);

// Pointer of the function eSTREAM project
set_t set[] = { (set_t)salsa_set_key_and_iv,
		(set_t)rabbit_set_key_and_iv,
		(set_t)hc128_set_key_and_iv,
		(set_t)sosemanuk_set_key_and_iv,
		(set_t)grain_set_key_and_iv,
		(set_t)mickey_set_key_and_iv,
		(set_t)trivium_set_key_and_iv };

test_t test[] = { (test_t)salsa_test_vectors,
		  (test_t)rabbit_test_vectors,
		  (test_t)hc128_test_vectors,
		  (test_t)sosemanuk_test_vectors,
		  (test_t)grain_test_vectors,
		  (test_t)mickey_test_vectors,
		  (test_t)trivium_test_vectors };

// Maximum length secret key and IV
const int keylen[7] = { 32, 16, 16, 32, 16, 10, 10 };
const int ivlen[7] =  {  8,  8, 16, 16, 12, 10, 10 };

// Test vectors
static void
test_vectors(void *ctx, int alg)
{
	set[alg](ctx, key, keylen[alg], iv, ivlen[alg]);

	test[alg](ctx);
}

int
main(int argc, char *argv[])
{
	union context context;
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
	case 0 : test_vectors(&(context.salsa), alg);
		 break;
	case 1 : test_vectors(&(context.rabbit), alg);
		 break;
	case 2 : test_vectors(&(context.hc128), alg);
		 break;
	case 3 : test_vectors(&(context.sosemanuk), alg);
		 break;
	case 4 : test_vectors(&(context.grain), alg);
		 break;
	case 5 : test_vectors(&(context.mickey), alg);
		 break;
	case 6 : test_vectors(&(context.trivium), alg);
		 break;
	default: printf("\nNo such algorithm!\n\n");
		 break;
	}

	return 0;
}

