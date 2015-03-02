/*
 * This program implements the stream cipher Grain-128
 * Author - M. Hell, T. Johansson, A. Maximov. Lund University, Sweden.
 * The Grain-128 home page - http://www.ecrypt.eu.org/stream/.
 * -----------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Assistant project manager: Lipin Boris (dzruyk).
 * Project manager: Grisha Sitkarev.
 * -----------------------
 * Russia, Komi Republic, Syktyvkar - 17.02.2015, version 1.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "grain.h"

// Maximum Grain-128 key length in bytes
#define GRAIN		16

// Linear feedback shift register
#define LFSR(s)		(s[0] ^ s[7] ^ s[38] ^ s[70] ^ s[81] ^ s[96])

// Non-linear feedback shift register
#define NFSR(b, s) 						\
	(s[ 0] ^ b[ 0]  ^  b[26] ^ b[56]  ^  b[91] ^ b[96]  ^	\
	(b[ 3] & b[67]) ^ (b[11] & b[13]) ^ (b[17] & b[18]) ^	\
	(b[27] & b[59]) ^ (b[40] & b[48]) ^ (b[61] & b[65]) ^	\
	(b[68] & b[84]))					\

// Boolean function
#define H(b, s)								\
	((b[12] & s[ 8]) ^ (s[13] & s[20]) ^ (b[95] & s[42]) ^		\
	 (s[60] & s[79]) ^ (b[12] & b[95]  &  s[95]))

// Output function
#define OUTBIT(b, s) 									\
	(b[2] ^ b[15] ^ b[36] ^ b[45] ^ b[64] ^ b[73] ^ b[89] ^ H(b, s) ^ s[93])

/*
 * Grain context
 * keylen - chiper key length in bits
 * key - chiper key
 * iv - initialization vector
 * b - register NFSR
 * s - register LFSR
*/
struct grain_context {
	int keylen;
	uint8_t key[16];
	uint8_t iv[12];
	uint8_t b[128];
	uint8_t s[128];
};

// Allocates memory for the grain_context
struct grain_context *
grain_context_new(void)
{
	struct grain_context *ctx;
	ctx = malloc(sizeof(*ctx));

	if(ctx == NULL)
		return NULL;
	
	memset(ctx, 0, sizeof(*ctx));

	return ctx;
}

// Delete grain_context
void
grain_context_free(struct grain_context **ctx)
{
	free(*ctx);
	*ctx = NULL;
}

// Keystream generation function
static uint8_t
grain_generate_keystream(struct grain_context *ctx)
{
	uint8_t lbit, nbit, outbit;
	int i, keylen;
	
	keylen = ctx->keylen;

	outbit = OUTBIT(ctx->b, ctx->s);
	nbit = NFSR(ctx->b, ctx->s);
	lbit = LFSR(ctx->s);

	for(i = 1; i < keylen; i++) {
		ctx->b[i-1] = ctx->b[i];
		ctx->s[i-1] = ctx->s[i];
	}

	ctx->b[keylen-1] = nbit;
	ctx->s[keylen-1] = lbit;

	return outbit;
}

// Key and IV initialization process
static void
grain_initialization_process(struct grain_context *ctx)
{
	uint8_t outbit;
	int i;

	for(i = 0; i < 96; i++) {
		ctx->b[i] = (ctx->key[i/8] >> (i & 0x7)) & 0x1;
		ctx->s[i] = (ctx->iv[i/8] >> (i & 0x7)) & 0x1;
	}

	for(i = 96; i < ctx->keylen; i++) {
		ctx->b[i] = (ctx->key[i/8] >> (i & 0x7)) & 0x1;
		ctx->s[i] = 0x1;
	}
	
	for(i = 0; i < 256; i++) {
		outbit = grain_generate_keystream(ctx);
		ctx->b[127] ^= outbit;
		ctx->s[127] ^= outbit;
	}
}

// Fill the grain_context (key adn iv)
// Return value: 0 (if all is well), -1 (is all bad)
int
grain_set_key_and_iv(struct grain_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[12])
{
	if((keylen <= GRAIN) && (keylen > 0))
		ctx->keylen = keylen * 8;
	else
		return -1;
	
	memcpy(ctx->key, key, keylen);
	memcpy(ctx->iv, iv, 12);

	grain_initialization_process(ctx);

	return 0;
}

/*
 * Grain-128 encrypt function
 * ctx - pointer on grain_context
 * buf - pointer on buffer data
 * buflen - length the data buffer
 * out - pointer on output buffer
*/
void
grain_encrypt(struct grain_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	uint8_t k = 0;
	uint32_t i, j;	

	for(i = 0; i < buflen; i++) {
		k = 0;

		for(j = 0; j < 8; j++)
			k |= (grain_generate_keystream(ctx) << j);

		out[i] = buf[i] ^ k;
	}
}

// Grain-128 decrypt function. See grain_encrypt
void
grain_decrypt(struct grain_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	grain_encrypt(ctx, buf, buflen, out);
}

// Test vectors print
void
grain_test_vectors(struct grain_context *ctx)
{
	uint8_t keystream[16];
	int i, j;

	for(i = 0; i < 16; i++) {
		keystream[i] = 0;

		for(j = 0; j < 8; j++)
			keystream[i] |= (grain_generate_keystream(ctx) << j);
	}
	
	printf("\nTest vector for the Grain-128:\n");
	
	printf("\nKey:       ");
	
	for(i = 0; i < 16; i++)
			printf("%02x ", ctx->key[i]);

	printf("\nIV:        ");
	
	for(i = 0; i < 12; i++)
		printf("%02x ", ctx->iv[i]);
	
	printf("\nKeystream: ");

	for(i = 0; i < 16; i++)
			printf("%02x ", keystream[i]);
		
	printf("\n\n");
}

