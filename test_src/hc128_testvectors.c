/*
 * Test vectors for the HC-128 algorithm
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../src/hc128.h"

int
main(void)
{
	uint8_t key1[16] = { 0x80, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00 };
	
	uint8_t key2[16] = { 0x01, 0x23, 0x45, 0x67,
			     0x89, 0xAB, 0xCD, 0xEF,
			     0x01, 0x23, 0x45, 0x67,
			     0x89, 0xAB, 0xCD, 0xEF };

	uint8_t iv1[16] = { 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00 };
	
	uint8_t iv2[16] = { 0x01, 0x23, 0x45, 0x67,
			    0x89, 0xAB, 0xCD, 0xEF,
			    0x01, 0x23, 0x45, 0x67,
			    0x89, 0xAB, 0xCD, 0xEF };

	struct hc128_context *ctx;

	if((ctx = hc128_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}
	
	if(hc128_set_key_and_iv(ctx, (uint8_t *)key1, 16, iv1, 16)) {
		printf("HC128 context filling error!\n");
		exit(1);
	}
	
	hc128_test_vectors(ctx);

	hc128_context_free(&ctx);

	if((ctx = hc128_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}

	if(hc128_set_key_and_iv(ctx, (uint8_t *)key2, 16, iv2, 16)) {
		printf("HC128 context filling error!\n");
		exit(1);
	}
	
	hc128_context_free(&ctx);

	return 0;
}

