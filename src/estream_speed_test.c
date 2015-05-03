/*
 * This program tests the algorithms eSTREAM project to speed perfomance
 * Makefile: Makefile_speed
 * Compile: make -f Makefile_speed
 * Example: ./estream_speed_test -h ./estream_speed_test -a 1 
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/time.h>

#include "estream.h"

#define BUFLEN		100000000

// Struct for time value
struct timeval t1, t2;

uint8_t buf[BUFLEN];
uint8_t out1[BUFLEN];
uint8_t out2[BUFLEN];

// Secret key
uint8_t key[32] = { 0x00, 0x11, 0x22, 0x33,
		    0x44, 0x55, 0x66, 0x77,
		    0x88, 0x99, 0xAA, 0xBB,
		    0xCC, 0xDD, 0xEE, 0xFF,
		    0x00, 0x11, 0x22, 0x33,
		    0x44, 0x55, 0x66, 0x77,
		    0x88, 0x99, 0xAA, 0xBB,
		    0xCC, 0xDD, 0xEE, 0xFF };

// Vector initilization
uint8_t iv[16] = { 0x01, 0x23, 0x45, 0x67,
		   0x89, 0xAB, 0xCD, 0xEF,
		   0x01, 0x23, 0x45, 0x67,
		   0x89, 0xAB, 0xCD, 0xEF };

// Time start
static void
time_start(void)
{
	gettimeofday(&t1, NULL);
}

// Time stop
static uint32_t
time_stop(void)
{
	gettimeofday(&t2, NULL);

	t2.tv_sec -= t1.tv_sec;
	t2.tv_usec -= t1.tv_usec;

	if(t2.tv_usec < 0) {
		t2.tv_sec--;
		t2.tv_usec += 1000000;
	}
	
	return (t2.tv_sec * 1000 + t2.tv_usec/1000);
}

// Manual
static void
help(void)
{
	printf("\nThis program provides the user interface for testing algorithms project eSTREAM on speed test!\n");
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
typedef void (*crypt_t)(void *ctx, uint8_t *buf, uint32_t buflen, uint8_t *out);

// Pointer of the function eSTREAM project
set_t set[] = { (set_t)salsa_set_key_and_iv,
		(set_t)rabbit_set_key_and_iv,
		(set_t)hc128_set_key_and_iv,
		(set_t)sosemanuk_set_key_and_iv,
		(set_t)grain_set_key_and_iv,
		(set_t)mickey_set_key_and_iv,
		(set_t)trivium_set_key_and_iv };

crypt_t crypt[] = { (crypt_t)salsa_crypt,
		    (crypt_t)rabbit_crypt,
		    (crypt_t)hc128_crypt,
		    (crypt_t)sosemanuk_crypt,
		    (crypt_t)grain_crypt,
		    (crypt_t)mickey_crypt,
		    (crypt_t)trivium_crypt };

// Maximum length secret key and IV
const int keylen[7] = { 32, 16, 16, 32, 16, 10, 10 };
const int ivlen[7] =  {  8,  8, 16, 16, 12, 10, 10 };

// Speed test
static void
speed_test(void *ctx, int alg)
{
	time_start();

	if(set[alg](ctx, key, keylen[alg], iv, ivlen[alg])) {
		printf("Context filling error!\n");
		exit(1);
	}

	crypt[alg](ctx, buf, BUFLEN, out1);

	if(set[alg](ctx, key, keylen[alg], iv, ivlen[alg])) {
		printf("Context filling error!\n");
		exit(1);
	}

	crypt[alg](ctx, out1, BUFLEN, out2);

	printf("\nRun time of the %d bytes - %d\n\n", BUFLEN, time_stop());
}

int
main(int argc, char *argv[])
{
	union context context;
	int res, alg = 0;

	const struct option long_option [] = {
		{"algorithm", 1, NULL, 'a'},
		{"help",      0, NULL, 'h'},
		{0, 	      0, NULL,  0 }
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

	// Select algorithm
	switch(alg) {
	case 0 : printf("\nSalsa speed test!\n");
		 speed_test(&(context.salsa), alg);
		 break;
	case 1 : printf("\nRabbit speed test!\n");
		 speed_test(&(context.rabbit), alg);
		 break;
	case 2 : printf("\nHC128 speed test!\n");
		 speed_test(&(context.hc128), alg);
		 break;
	case 3 : printf("\nSosemanuk speed test!\n");
		 speed_test(&(context.sosemanuk), alg);
		 break;
	case 4 : printf("\nGrain speed test!\n");
		 speed_test(&(context.grain), alg);
		 break;
	case 5 : printf("\nMickey speed test!\n");
		 speed_test(&(context.mickey), alg);
		 break;
	case 6 : printf("\nTrivium speed test!\n");
		 speed_test(&(context.trivium), alg);
		 break;
	default: printf("\nNo such algorithm!\n");
		 break;
	}
	
	return 0;
}

