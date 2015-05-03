/* 
 * This program implements the RABBIT-128 algorithm.
 * Developed Martin Boesgaard, Mette Vesterager, Thomas Christensen, Erik Zenner.
 * Company CRYPTICO A/S Fruebjergvej 3, Copenhagen, Denmark
 * The RABBIT-128 home page - http://www.ecrypt.eu.org/stream/.
 * -----------------------
 * Author: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Assistant project manager: Lipin Boris (dzruyk).
 * Project manager: Grisha Sitkarev.
 * -----------------------
 * Russia, Komi Republic, Syktyvkar - 17.11.2014, version 1. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "rabbit.h"

#define RABBIT	16

#define ROTL32(v, n)	((v << n) | (v >> (32 - n)))

// Selecting the byte order
#if __BYTE_ORDER == __BIG_ENDIAN
#define U32TO32(x)								\
	((x << 24) | ((x << 8) & 0xFF0000) | ((x >> 8) & 0xFF00) | (x >> 24))
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define U32TO32(x)	(x)
#else
#error unsuported byte order
#endif

#define U8TO32_LITTLE(p) 					  \
	(((uint32_t)((p)[0])      ) | ((uint32_t)((p)[1]) << 8) | \
	 ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

// G-func the RABBIT-128 algorithm. The upper 32 bits XOR the lower 32 bits
#define G_FUNC(x, y) {						  \
	uint32_t a, b, h;					  \
	a = x & 0xFFFF;						  \
	b = x >> 16;					 	  \
	h = ((((a*a) >> 17) + (a*b)) >> 15) + b*b;		  \
	y = h ^ (x*x);						  \
}

// Constant of the algorithm for the function rabbit_next_state 
#define A0	0x4D34D34D
#define A1	0xD34D34D3
#define A2	0x34D34D34
#define A3	A0
#define A4	A1
#define A5	A2
#define A6	A0
#define A7	A1

// Rabbit initialization function
static void
rabbit_init(struct rabbit_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

// Calculate the next internal state
static void
rabbit_next_state(struct rabbit_context *ctx)
{
	uint32_t g[8], c_old[8];
	int i;

	memcpy(c_old, ctx->c, sizeof(ctx->c));
	
	ctx->c[0] = ctx->c[0] + A0 + ctx->carry;
	ctx->c[1] = ctx->c[1] + A1 + (ctx->c[0] < c_old[0]);
	ctx->c[2] = ctx->c[2] + A2 + (ctx->c[1] < c_old[1]);
	ctx->c[3] = ctx->c[3] + A3 + (ctx->c[2] < c_old[2]);
	ctx->c[4] = ctx->c[4] + A4 + (ctx->c[3] < c_old[3]);
	ctx->c[5] = ctx->c[5] + A5 + (ctx->c[4] < c_old[4]);
	ctx->c[6] = ctx->c[6] + A6 + (ctx->c[5] < c_old[5]);
	ctx->c[7] = ctx->c[7] + A7 + (ctx->c[6] < c_old[6]);
	ctx->carry = (ctx->c[7] < c_old[7]);
	
	for(i = 0; i < 8; i++)
		G_FUNC((ctx->x[i] + ctx->c[i]), g[i]);

	ctx->x[0] = g[0] + ROTL32(g[7], 16) + ROTL32(g[6], 16);
	ctx->x[1] = g[1] + ROTL32(g[0], 8) + g[7];
	ctx->x[2] = g[2] + ROTL32(g[1], 16) + ROTL32(g[0], 16);
	ctx->x[3] = g[3] + ROTL32(g[2], 8) + g[1];
	ctx->x[4] = g[4] + ROTL32(g[3], 16) + ROTL32(g[2], 16);
	ctx->x[5] = g[5] + ROTL32(g[4], 8) + g[3];
	ctx->x[6] = g[6] + ROTL32(g[5], 16) + ROTL32(g[4], 16);
	ctx->x[7] = g[7] + ROTL32(g[6], 8) + g[5];
}

// Setup secret key
static void
rabbit_key_setup(struct rabbit_context *ctx)
{
	uint32_t k0, k1, k2, k3;
	int i;

	// Copy the secret key into 4 parts
	k0 = U8TO32_LITTLE((ctx->key + 0));
	k1 = U8TO32_LITTLE((ctx->key + 4));
	k2 = U8TO32_LITTLE((ctx->key + 8));
	k3 = U8TO32_LITTLE((ctx->key + 12));
	
	ctx->x[0] = k0;
	ctx->x[2] = k1;
	ctx->x[4] = k2;
	ctx->x[6] = k3;
	ctx->x[1] = (k3 << 16) | (k2 >> 16);
	ctx->x[3] = (k0 << 16) | (k3 >> 16);
	ctx->x[5] = (k1 << 16) | (k0 >> 16);
	ctx->x[7] = (k2 << 16) | (k1 >> 16);

	ctx->c[0] = (k2 << 16) | (k2 >> 16);
	ctx->c[2] = (k3 << 16) | (k3 >> 16);
	ctx->c[4] = (k0 << 16) | (k0 >> 16);
	ctx->c[6] = (k1 << 16) | (k1 >> 16);
	ctx->c[1] = (k0 >> 16) | (k1 << 16);
	ctx->c[3] = (k1 >> 16) | (k2 << 16);
	ctx->c[5] = (k2 >> 16) | (k3 << 16);
	ctx->c[7] = (k3 >> 16) | (k0 << 16);
	
	ctx->carry = 0;

	for(i = 0; i < 4; i++)
		rabbit_next_state(ctx);	
	
	// (i+4) & 0x7 = (i+4) % 8
	for(i = 0; i < 8; i++)
		ctx->c[i] ^= ctx->x[(i+4) & 0x7];
}

// Setup vector initialization
static void
rabbit_iv_setup(struct rabbit_context *ctx)
{
	uint32_t iv0, iv1, iv2, iv3;
	int i;
	
	iv0 = U8TO32_LITTLE((ctx->iv + 0));
	iv1 = U8TO32_LITTLE((ctx->iv + 4));
	iv2 = (iv1 & 0xffff0000) | (iv0 >> 16);
	iv3 = (iv1 << 16) | (iv0 & 0x0000ffff);
		
	ctx->c[0] ^= iv0;
	ctx->c[1] ^= iv2;
	ctx->c[2] ^= iv1;
	ctx->c[3] ^= iv3;
	ctx->c[4] ^= iv0;
	ctx->c[5] ^= iv2;
	ctx->c[6] ^= iv1;
	ctx->c[7] ^= iv3;
	
	for(i = 0; i < 4; i++)
		rabbit_next_state(ctx);
}

// Fill the rabbit context (key and iv)
// Return value: 0 (if all is well), -1 (if all bad) 
int
rabbit_set_key_and_iv(struct rabbit_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[8], const int ivlen)
{
	rabbit_init(ctx);
	
	if((keylen > 0) && (keylen <= RABBIT))
		ctx->keylen = keylen;
	else
		return -1;
	
	if((ivlen > 0) && (ivlen <= 8))
		ctx->ivlen = ivlen;
	else
		return -1;
	
	memcpy(ctx->key, key, ctx->keylen);
	memcpy(ctx->iv, iv, ctx->ivlen);
	
	// Setup key and vector initialization
	rabbit_key_setup(ctx);
	rabbit_iv_setup(ctx);

	return 0;
}

/* 
 * RABBIT crypt algorithm.
 * ctx - pointer on RABBIT context
 * buf - pointer on buffer data
 * buflen - length the data buffer
 * out - pointer on output array
*/
void
rabbit_crypt(struct rabbit_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	uint32_t keystream[4];
	uint32_t i;
	
	for(; buflen >= 16; buflen -= 16, buf += 16, out += 16) {
		rabbit_next_state(ctx);

		*(uint32_t *)(out +  0) = *(uint32_t *)(buf +  0) ^ U32TO32((ctx->x[0] ^
			(ctx->x[5] >> 16) ^ (ctx->x[3] << 16)));
		*(uint32_t *)(out +  4) = *(uint32_t *)(buf +  4) ^ U32TO32((ctx->x[2] ^
			(ctx->x[7] >> 16) ^ (ctx->x[5] << 16)));
		*(uint32_t *)(out +  8) = *(uint32_t *)(buf +  8) ^ U32TO32((ctx->x[4] ^
			(ctx->x[1] >> 16) ^ (ctx->x[7] << 16)));
		*(uint32_t *)(out + 12) = *(uint32_t *)(buf + 12) ^ U32TO32((ctx->x[6] ^ 
			(ctx->x[3] >> 16) ^ (ctx->x[1] << 16)));
	}
	
	if(buflen) {
		rabbit_next_state(ctx);
		
		keystream[0] = U32TO32((ctx->x[0] ^ (ctx->x[5] >> 16) ^ (ctx->x[3] << 16)));
		keystream[1] = U32TO32((ctx->x[2] ^ (ctx->x[7] >> 16) ^ (ctx->x[5] << 16)));
		keystream[2] = U32TO32((ctx->x[4] ^ (ctx->x[1] >> 16) ^ (ctx->x[7] << 16)));
		keystream[3] = U32TO32((ctx->x[6] ^ (ctx->x[3] >> 16) ^ (ctx->x[1] << 16)));

		for(i = 0; i < buflen; i++)
			out[i] = buf[i] ^ ((uint8_t *)keystream)[i];	
	}
}

#if __BYTE_ORDER == __BIG_ENDIAN
#define PRINT_U32TO32(x) \
	(printf("%02x %02x %02x %02x ", (x >> 24), ((x >> 16) & 0xFF), ((x >> 8) & 0xFF), (x & 0xFF)))
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define PRINT_U32TO32(x) \
	(printf("%02x %02x %02x %02x ", (x & 0xFF), ((x >> 8) & 0xFF), ((x >> 16) & 0xFF), (x >> 24)))
#else
#error unsupported byte order
#endif

// Test vectors print
void
rabbit_test_vectors(struct rabbit_context *ctx)
{
	uint32_t keystream[4];
	int i;

	rabbit_next_state(ctx);
	
	keystream[0] = U32TO32((ctx->x[0] ^ (ctx->x[5] >> 16) ^ (ctx->x[3] << 16)));
	keystream[1] = U32TO32((ctx->x[2] ^ (ctx->x[7] >> 16) ^ (ctx->x[5] << 16)));
	keystream[2] = U32TO32((ctx->x[4] ^ (ctx->x[1] >> 16) ^ (ctx->x[7] << 16)));
	keystream[3] = U32TO32((ctx->x[6] ^ (ctx->x[3] >> 16) ^ (ctx->x[1] << 16)));

	printf("\n Test vectors for the Rabbit:\n");

	printf("\nKey:       ");

	for(i = 0; i < 16; i++)
		printf("%02x ", ctx->key[i]);
	
	printf("\nIV:        ");

	for(i = 0; i < 8; i++)
		printf("%02x ", ctx->iv[i]);
	
	printf("\nKeystream: ");
	
	for(i = 0; i < 4; i++)
		PRINT_U32TO32(keystream[i]);
	
	printf("\n\n");
}

