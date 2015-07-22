/*
 * This program implements the GOST 28147-89 algorithm
 * Author - 8th KGB
 * ----------------
 * Developer: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * ----------------
 * Russia, Komi Republic, Syktyvkar - 03.06.2015.
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "gost89.h"
#include "macro.h"

// Maximum GOST 28147-89 key length in bytes
#define GOST89			32

// GOST 28147-89 constant
#define GOST_C1			0x01010101U
#define GOST_C2			0x01010104U
#define GOST_2EXP32M1		0xFFFFFFFFU

// n << 2 = n * 4
// (0x12345678 >> 0) & 0xF = 0x8 (last 4 bits)
#define SBOX(x, n)	(sbox[(n << 2) + ((x >> n) & 0xF)] << n)

// GOST89 gamma update function
#define GOST89_GAMMA_UPDATE(gamma) {	\
	uint32_t *p;			\
	int c, temp;			\
	p = gamma;			\
	p[0] += GOST_C1;		\
	c = GOST_2EXP32M1 - p[1];	\
	temp = (GOST_C2 > c) ? 1 : 0;	\
	p[1] += GOST_C2;		\
	p[1] += temp;			\
}

// Well-known Sbox used by Central Bank of Russia
uint8_t sbox[] = {
	4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3,
	14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9,
	5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11,
	7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3,
	6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2,
	4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14,
	13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12,
	1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 };


// GOST89 initialization function
static void
gost89_init(struct gost89_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

// Fill the gost89_context (secret key)
// Return value: 0 (if all is well), -1 (is all bad)
// Gamma - 64-bits length
int
gost89_set_key_and_gamma(struct gost89_context *ctx, const uint8_t *key, const int keylen, const uint8_t gamma[8])
{
	gost89_init(ctx);

	if((keylen > 0) && (keylen <= GOST89))
		ctx->keylen = keylen;
	else
		return -1;
	
	memcpy(ctx->key, key, keylen);
	memcpy(ctx->gamma, gamma, sizeof(ctx->gamma));

	gost89_encrypt(ctx, ctx->gamma);

	return 0;
}

// Basic function of the GOST89
static void
gost89_basic(struct gost89_context *ctx, uint32_t *n1, uint32_t *n2, const int x)
{
	uint32_t res;

	res = *n1 + ctx->key[x];
	
	res = SBOX(res,  0) | SBOX(res,  4) | SBOX(res,  8) | SBOX(res, 12) |
	      SBOX(res, 16) | SBOX(res, 20) | SBOX(res, 24) | SBOX(res, 28);

	res = ROTL32(res, 11);

	res ^= *n2;
	*n2 = *n1;
	*n1 = res;
}

/*
 * GOST89 encrypt algorithm in mode of simple replacement
 * ctx - pointer on gost89_context
 * n - pointer input buffer data (64 bytes)
*/
void
gost89_encrypt(struct gost89_context *ctx, uint32_t *block)
{
	uint32_t *n1, *n2, temp;
	int i, x;
	int key_order[32] = { 0, 1, 2, 3, 4, 5, 6, 7,
			      0, 1, 2, 3, 4, 5, 6, 7,
			      0, 1, 2, 3, 4, 5, 6, 7,
			      7, 6, 5, 4, 3, 2, 1, 0 };
	
	n1 = block;
	n2 = n1 + 1;

	for(i = 0; i < 32; i++) {
		x = key_order[i];
		gost89_basic(ctx, n1, n2, x);
	}

	temp = *n1;
	*n1 = *n2;
	*n2 = temp;
}

// GOST89 decryption function. See gost89_encrypt
void
gost89_decrypt(struct gost89_context *ctx, uint32_t *block)
{
	uint32_t *n1, *n2, temp;
	int i, x;
	int key_order[32] = { 0, 1, 2, 3, 4, 5, 6, 7,
			      7, 6, 5, 4, 3, 2, 1, 0,
			      7, 6, 5, 4, 3, 2, 1, 0,
			      7, 6, 5, 4, 3, 2, 1, 0 };

	n1 = block;
	n2 = n1 + 1;

	for(i = 0; i < 32; i++) {
		x = key_order[i];
		gost89_basic(ctx, n1, n2, x);
	}

	temp = *n1;
	*n1 = *n2;
	*n2 = temp;
}

/*
 * GOST 28147-89 encrypt algorithm in mode XOR
 * ctx - pointer on gost89 context
 * buf - pinter on input buffer data
 * out - pinter on output buffer data
 * buflen - length the data buffer
*/
void
gost89_gamma_crypt(struct gost89_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	int i;
	uint32_t gamma[2];

	for(; buflen >= 8; buflen -= 8, buf += 8, out += 8) {
		GOST89_GAMMA_UPDATE(ctx->gamma);
		gost89_encrypt(ctx, ctx->gamma);

		*(uint32_t *)(out + 0) = *(uint32_t *)(buf + 0) ^ U32TO32(ctx->gamma[0]);
		*(uint32_t *)(out + 4) = *(uint32_t *)(buf + 4) ^ U32TO32(ctx->gamma[1]);
	}

	if(buflen > 0) {
		GOST89_GAMMA_UPDATE(ctx->gamma);
		gost89_encrypt(ctx, ctx->gamma);

		gamma[0] = U32TO32(ctx->gamma[0]);
		gamma[1] = U32TO32(ctx->gamma[1]);

		for(i = 0; i < 4; i++)
			out[i] = buf[i] ^ ((uint8_t *)gamma)[i];
	}
}

