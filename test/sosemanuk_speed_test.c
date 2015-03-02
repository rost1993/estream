// This program tests the library sosemanuk.h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "../lib/sosemanuk.h"

#define BUFLEN		10000000

// Struct for time value
struct timeval t1, t2;

uint8_t buf[BUFLEN];
uint8_t out1[BUFLEN];
uint8_t out2[BUFLEN];
uint8_t key[32];
uint8_t iv[16];

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
	struct sosemanuk_context *ctx;
	//uint32_t i;

	memset(buf, 'q', sizeof(buf));
	memset(key, 'k', sizeof(key));
	memset(iv, 'i', sizeof(iv));

	time_start();

	/*for(i = 0; i < BUFLEN; i++)
		printf("%c ", (char)buf[i]);
	printf("\n\n\n");*/

	if((ctx = sosemanuk_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}

	if(sosemanuk_set_key_and_iv(ctx, (uint8_t *)key, 32, iv)) {
		printf("Mickey context filling error!\n");
		exit(1);
	}

	sosemanuk_encrypt(ctx, buf, BUFLEN, out1);

	/*for(i = 0; i < BUFLEN; i++)
		printf("%c ", (char)out1[i]);
	printf("\n\n\n");*/

	if(sosemanuk_set_key_and_iv(ctx, (uint8_t *)key, 32, iv)) {
		printf("Mickey context filling error!\n");
		exit(1);
	}

	sosemanuk_decrypt(ctx, out1, BUFLEN, out2);

	sosemanuk_context_free(&ctx);

	/*for(i = 0; i < BUFLEN; i++)
		printf("%c ", (char)out2[i]);
	printf("\n\n\n");*/

	printf("Run time = %d\n\n", time_stop());

	return 0;
}

