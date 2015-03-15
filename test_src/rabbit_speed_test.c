// This program tests the library rabbit.h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "../src/rabbit.h"

#define BUFLEN	10000000

// Struct for time value
struct timeval t1, t2;

uint8_t buf[BUFLEN];
uint8_t out1[BUFLEN];
uint8_t out2[BUFLEN];
uint8_t key[16];
uint8_t iv[8];

static void
time_start(void)
{
	gettimeofday(&t1, NULL);
}

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
	struct rabbit_context *ctx;

	memset(buf, 'q', sizeof(buf));
	memset(key, 'k', sizeof(key));
	memset(iv, 'i', sizeof(iv));
	
	time_start();

	if((ctx = rabbit_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}

	if(rabbit_set_key_and_iv(ctx, (uint8_t *)key, 16, iv, 8)) {
		printf("Rabbit context filling error!\n");
		exit(1);
	}
	
	rabbit_encrypt(ctx, buf, BUFLEN, out1);
	
	if(rabbit_set_key_and_iv(ctx, (uint8_t *)key, 16, iv, 8)) {
		printf("Rabbit context felling error 2!\n");
		exit(1);
	}
	
	rabbit_decrypt(ctx, out1, BUFLEN, out2);
	
	rabbit_context_free(&ctx);
	
	printf("Run time = %d\n\n", time_stop());

	return 0;
}

