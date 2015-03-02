/*
 * Test vectors for the Sosemanuk algorithm
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../lib/sosemanuk.h"

int
main(void)
{
	uint8_t key1[32] = { 0x00, 0x11, 0x22, 0x33,
			     0x44, 0x55, 0x66, 0x77,
			     0x88, 0x99, 0xAA, 0xBB,
			     0xCC, 0xDD, 0xEE, 0xFF,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00 };

	uint8_t key2[32] = { 0x01, 0x23, 0x45, 0x67,
			     0x89, 0xAB, 0xCD, 0xEF,
			     0x01, 0x23, 0x45, 0x67,
			     0x89, 0xAB, 0xCD, 0xEF,
			     0x01, 0x23, 0x45, 0x67,
			     0x89, 0xAB, 0xCD, 0xEF,
			     0x01, 0x23, 0x45, 0x67,
			     0x89, 0xAB, 0xCD, 0xEF };

	uint8_t iv1[16] = { 0x88, 0x99, 0xAA, 0xBB,
			    0xCC, 0xDD, 0xEE, 0xFF,
			    0x00, 0x11, 0x22, 0x33,
			    0x44, 0x55, 0x66, 0x77 };
	
	uint8_t iv2[16] = { 0x01, 0x23, 0x45, 0x67,
			    0x89, 0xAB, 0xCD, 0xEF,
			    0x01, 0x23, 0x45, 0x67,
			    0x89, 0xAB, 0xCD, 0xEF };

	struct sosemanuk_context *ctx;

	if((ctx = sosemanuk_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}

	if(sosemanuk_set_key_and_iv(ctx, key1, 32, iv1)) {
		printf("Filling sosemanuk context error!\n");
		exit(1);
	}
	
	sosemanuk_test_vectors(ctx);

	if(sosemanuk_set_key_and_iv(ctx, key2, 32, iv2)) {
		printf("Filling sosemanuk context error!\n");
		exit(1);
	}

	sosemanuk_test_vectors(ctx);

	sosemanuk_context_free(&ctx);

	return 0;
}
