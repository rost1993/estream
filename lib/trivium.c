/* 
 * This program implements the Trivium algorithm.
 * Author Christophe De Canniere and Bart Preneel Katholieke Universiteit Leuven.
 * The Trivium home page - http://www.ecrypt.eu.org/stream/.
 * ---------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Assistant project manager: Lipin Boris (dzruyk).
 * Project manager: Grisha Sitkarev.
 * ---------------------
 * Russia, Komi Republic, Syktyvkar - 09.01.2015, version 1.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "trivium.h"

#define TRIVIUM		10

// Selecting the byte order
#if __BYTE_ORDER == __BIG_ENDIAN
#define U32TO32(x)								\
	((x << 24) | ((x << 8) & 0xFF0000) | ((x >> 8) & 0xFF00) | (x >> 24))
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define U32TO32(x)	(x)
#else
#error unsupported byte order
#endif

#define U8TO32_LITTLE(p) 	     	\
	(((uint32_t)((p)[0])) 	   | 	\
	((uint32_t)((p)[1]) << 8)  | 	\
	((uint32_t)((p)[2]) << 16) | 	\
	((uint32_t)((p)[3]) << 24))

// Macros bit allocation
#define S64(a, b, c)	((a << (96 - c))  | (b >> (c - 64)))
#define S96(a, b, c)	((a << (128 - c)) | (b >> (c - 96)))

// Macros update the keystream
#define T(w) { 							\
	t1 = S64(w[2], w[1], 66) ^ S64(w[2], w[1], 93); 	\
	t2 = S64(w[5], w[4], 69) ^ S64(w[5], w[4], 84); 	\
	t3 = S64(w[8], w[7], 66) ^ S96(w[9], w[8], 111);	\
}

#define UPDATE(w) {									\
	t1 ^= (S64(w[2], w[1], 91) & S64(w[2], w[1], 92)) ^ S64(w[5], w[4], 78);        \
	t2 ^= (S64(w[5], w[4], 82) & S64(w[5], w[4], 83)) ^ S64(w[8], w[7], 87);        \
	t3 ^= (S96(w[9], w[8], 109) & S96(w[9], w[8], 110)) ^ S64(w[2], w[1], 69);      \
											\
	w[2] = w[1];                                                                    \
	w[1] = w[0];                                                                    \
	w[0] = t3;                                                                      \
											\
	w[5] = w[4];                                                                    \
	w[4] = w[3];                                                                    \
	w[3] = t1;                                                                      \
											\
	w[9] = w[8];                                                                    \
	w[8] = w[7];                                                                    \
	w[7] = w[6];                                                                    \
	w[6] = t2;									\
}

// Macro update the array w
#define WORK_1(w) {		\
	uint32_t t1, t2, t3;	\
	T(w);			\
	UPDATE(w);		\
}

// Macro generate keystream (z)
#define WORK_2(w, z) {			\
	uint32_t t1, t2, t3;		\
	T(w);				\
	z = t1 ^ t2 ^ t3;		\
	UPDATE(w);			\
}

// Trivium initialization function
static void
trivium_init(struct trivium_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

// Function key and iv setup
static void
trivium_keysetup(struct trivium_context *ctx)
{
	uint32_t w[10];
	uint8_t s[40];
	int i;

	memset(s, 0, sizeof(s));

	for(i = 0; i < ctx->keylen; i++)
		s[i] = ctx->key[i];
	
	for(i = 0; i < ctx->ivlen; i++)
		s[i + 12] = ctx->iv[i];

	s[37] = 0x70;
	
	w[0] = U8TO32_LITTLE(s + 0);
	w[1] = U8TO32_LITTLE(s + 4);
	w[2] = U8TO32_LITTLE(s + 8);
	w[3] = U8TO32_LITTLE(s + 12);
	w[4] = U8TO32_LITTLE(s + 16);
	w[5] = U8TO32_LITTLE(s + 20);
	w[6] = U8TO32_LITTLE(s + 24);
	w[7] = U8TO32_LITTLE(s + 28);
	w[8] = U8TO32_LITTLE(s + 32);
	w[9] = U8TO32_LITTLE(s + 36);

	for(i = 0; i < 4 * 9; i++)
		WORK_1(w);
	
	memcpy(ctx->w, w, sizeof(w));
}

// Fill the trivium context (key and iv)
// Return value: 0 (if all is well), -1 is all bad
int
trivium_set_key_and_iv(struct trivium_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[10], const int ivlen)
{
	trivium_init(ctx);
	
	if((keylen > 0) && (keylen <= TRIVIUM))
		ctx->keylen = keylen;
	else
		return -1;
	
	if((ivlen > 0) && (ivlen <= 10))
		ctx->ivlen = ivlen;
	else
		return -1;
	
	memcpy(ctx->key, key, keylen);
	memcpy(ctx->iv, iv, 10);
	
	trivium_keysetup(ctx);
	
	return 0;
}

/*
 * Trivium crypt algorithm.
 * ctx - pointer on trivium context
 * buf - pointer on buffer data
 * buflen - length the data buffer
 * out - pointer on output array
*/
void
trivium_crypt(struct trivium_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	uint32_t z, w[10], i;

	memcpy(w, ctx->w, sizeof(w));

	for(; buflen >= 4; buflen -= 4, buf += 4, out += 4) {
		WORK_2(w, z);
		
		*(uint32_t *)(out + 0) = *(uint32_t *)(buf + 0) ^ U32TO32(z);
	}

	if(buflen) {
		WORK_2(w, z);
		
		for(i = 0; i < buflen; i++, z >>= 8)
			out[i] = buf[i] ^ (uint8_t)(z);
	}
	
	memcpy(ctx->w, w, sizeof(w));
}

#if __BYTE_ORDER == __BIG_ENDIAN
#define PRINT_U32TO32(x)\
	(printf("%02x %02x %02x %02x ", (x >> 24), ((x >> 16) & 0xFF), ((x >> 8) & 0xFF), (x & 0xFF)))
#else
#define PRINT_U32TO32(x)\
	(printf("%02x %02x %02x %02x ", (x & 0xFF), ((x >> 8) & 0xFF), ((x >> 16) & 0xFF), (x >> 24)))
#endif

// Test vectors print
void
trivium_test_vectors(struct trivium_context *ctx)
{
	uint32_t z, w[10], i;
	
	memcpy(w, ctx->w, sizeof(w));

	printf("\nTest vectors for the Trivium:\n");

	printf("\nKey:       ");

	for(i = 0; i < 10; i++)
		printf("%02x ", ctx->key[i]);
	
	printf("\nIV:        ");

	for(i = 0; i < 10; i++)
		printf("%02x ", ctx->iv[i]);

	printf("\nKeystream: ");

	for(i = 0; i < 10; i++) {
		WORK_2(w, z);
		PRINT_U32TO32(U32TO32(z));
	}
	
	printf("\n\n");
}

