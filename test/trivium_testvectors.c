/*
 * Test vectors for the Trivium algorithm
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../lib/trivium.h"

int
main(void)
{
	uint8_t key1[10] = { 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00 };
	
	uint8_t iv1[10] = { 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00 };
	
	uint8_t key2[10] = { 0x01, 0x23, 0x45, 0x67, 0x89,
			     0xAB, 0xCD, 0xEF, 0x00, 0x00 };
	
	uint8_t iv2[10] = { 0x01, 0x23, 0x45, 0x67, 0x89,
			    0xAB, 0xCD, 0xEF, 0x00, 0x00 };
	
	struct trivium_context *ctx;

	if((ctx = trivium_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}

	if(trivium_set_key_and_iv(ctx, key1, 10, iv1)) {
		printf("Trivium context filling error!\n");
		exit(1);
	}
	
	trivium_test_vectors(ctx);

	if(trivium_set_key_and_iv(ctx, key2, 10, iv2)) {
		printf("Trivium context filling error!\n");
		exit(1);
	}
	
	trivium_test_vectors(ctx);

	trivium_context_free(&ctx);

	return 0;
}

