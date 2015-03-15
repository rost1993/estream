/*
 * Test vectors for the Rabbit algorithm
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../src/rabbit.h"

int
main(void)
{
	uint8_t key1[16] = { 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00 };
	
	uint8_t iv1[8] = { 0x27, 0x17, 0xF4, 0xD2,
			  0x1A, 0x56, 0xEB, 0xA6 };
	
	uint8_t key2[16] = { 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00 };

	uint8_t iv2[8] = { 0x59, 0x7E, 0x26, 0xC1,
			   0x75, 0xF5, 0x73, 0xC3 };
	
	struct rabbit_context *ctx;

	if((ctx = rabbit_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}
	
	if(rabbit_set_key_and_iv(ctx, key1, 16, iv1, 8)) {
		printf("Rabbit context filling error!\n");
		exit(1);
	}
	
	rabbit_test_vectors(ctx);

	rabbit_context_free(&ctx);

	if((ctx = rabbit_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}

	if(rabbit_set_key_and_iv(ctx, key2, 16, iv2, 8)) {
		printf("Rabbit context filling error!\n");
		exit(1);
	}
	
	rabbit_test_vectors(ctx);

	rabbit_context_free(&ctx);

	return 0;
}

