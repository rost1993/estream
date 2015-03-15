// This program tests the library salsa.h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "../src/salsa.h"

#define	BUFLEN	10000000
#define KEYLEN	32

// Struct for time value
struct timeval t1, t2;

uint8_t buf[BUFLEN];
uint8_t out1[BUFLEN];
uint8_t out2[BUFLEN];
uint8_t key[KEYLEN];
uint8_t iv[8];

// Function time measurement
static void
time_start(void)
{
	gettimeofday(&t1, NULL);
}

// Function time measurement
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

int 
main()
{
	struct salsa_context *ctx;

	memset(buf, 'q', sizeof(buf));
	memset(key, 'k', sizeof(key));
	memset(iv, 1, sizeof(iv));
	
	time_start();
	
	if((ctx = salsa_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}
	
	if (salsa_set_key_and_iv(ctx, (uint8_t *)key, KEYLEN, iv, 8)) {
		printf("Salsa context filling error!\n");
		exit(1);
	}
	
	salsa_encrypt(ctx, buf, BUFLEN, out1);
	
	if(salsa_set_key_and_iv(ctx, (uint8_t *)key, KEYLEN, iv, 8)) {
		printf("Salsa context filling error!\n");
		exit(1);
	}

	salsa_decrypt(ctx, out1, BUFLEN, out2);
	
	printf("Run time = %d\n\n", time_stop());
	
	salsa_context_free(&ctx);

	return 0;
}

