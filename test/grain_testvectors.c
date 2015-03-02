/*
 * Test vectors for the Grain algorithm
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../lib/grain.h"

int
main(void)
{
	struct grain_context *ctx;
	
	uint8_t key1[16] = { 0x00, 0x00, 0x00, 0x00,
		     	     0x00, 0x00, 0x00, 0x00,
		     	     0x00, 0x00, 0x00, 0x00,
		     	     0x00, 0x00, 0x00, 0x00 };
	
	uint8_t key2[16] = { 0x01, 0x23, 0x45, 0x67,
		     	     0x89, 0xAB, 0xCD, 0xEF,
		     	     0x12, 0x34, 0x56, 0x78,
		     	     0x9A, 0xBC, 0xDE, 0xF0 };

	uint8_t iv1[12] = { 0x00, 0x00, 0x00, 0x00,
		    	    0x00, 0x00, 0x00, 0x00,
		    	    0x00, 0x00, 0x00, 0x00 };
		   
	uint8_t iv2[12] = { 0x01, 0x23, 0x45, 0x67,
		    	    0x89, 0xAB, 0xCD, 0xEF,
		    	    0x12, 0x34, 0x56, 0x78 };

	if((ctx = grain_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}

	if(grain_set_key_and_iv(ctx, key1, 16, iv1)) {
		printf("Grain context filling error!\n");
		exit(1);
	}
	
	grain_test_vectors(ctx);

	if(grain_set_key_and_iv(ctx, key2, 16, iv2)) {
		printf("Grain context filling error!\n");
		exit(1);
	}
	
	grain_test_vectors(ctx);

	grain_context_free(&ctx);
	
	return 0;
}

