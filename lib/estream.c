/* 
 * This library implements the 7 algorithm eSTREAM project.
 * Algorithms: SALSA, RABBIT, HC128, SOSEMANUK, GRAIN, TRIVIUM, MICKEY 2.0.
 * The eSTREAM project home page - http://www.ecrypt.eu.org/stream/.
 * -----------------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Assistant project manager: Lipin Boris (dzruyk). 
 * Project manager: Grisha Sitkarev.
 * -----------------------------
 * Russia, Komi Republic, Syktyvkar - 12.03.2015.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "estream.h"

// Maximum key length in bytes
#define SALSA16		16
#define SALSA32		32
#define RABBIT		16
#define SOSEMANUK	32
#define HC128		16
#define GRAIN		16
#define MICKEY		10
#define TRIVIUM		10

// Service macros
//---------------------------------------------

// Cyclic shift to the left
#define ROTL32(v, n)	((v << n) | (v >> (32 - n)))

// Cyclic shift to the right
#define ROTR32(v, n)	((v >> n) | (v << (32 - n)))

// Selecting byte order for the 4 bytes
#if __BYTE_ORDER == __BIG_ENDIAN
#define U32TO32(x)                                                              \
	((x << 24) | ((x << 8) & 0xFF0000) | ((x >> 8) & 0xFF00) | (x >> 24))
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define U32TO32(x)      (x)
#else
#error unsupported byte order
#endif

// Little-endian 4 uint8_t in the uint32_t
#define U8TO32_LITTLE(p)                                                \
	(((uint32_t)((p)[0])     ) | ((uint32_t)((p)[1]) << 8) |        \
	((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

// Little-endian uint32_t in the 4 uint8_t
#define U32TO8_LITTLE(dst, val) {       \
        dst[0] = val;                   \
        dst[1] = val >> 8;              \
	dst[2] = val >> 16;             \
	dst[3] = val >> 24;             \
}

// Print 4 bytes depending on the byte order
#if __BYTE_ORDER == __BIG_ENDIAN
#define PRINT_U32TO32(x) \
	(printf("%02x %02x %02x %02x ", (x >> 24), ((x >> 16) & 0xFF), ((x >> 8) & 0xFF), (x & 0xFF)))
#else
#define PRINT_U32TO32(x) \
	(printf("%02x %02x %02x %02x ", (x & 0xFF), ((x >> 8) & 0xFF), ((x >> 16) & 0xFF), (x >> 24)))
#endif

//---------------------------------------------



// The stream algorithm Grain
//----------------------------------------------

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
 * ivlen - vector initialization length in bits
 * key - chiper key
 * iv - initialization vector
 * b - register NFSR
 * s - register LFSR
*/
struct grain_context {
	int keylen;
	int ivlen;
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
	ctx = (struct grain_context *)malloc(sizeof(*ctx));

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

	for(i = 0; i < ctx->ivlen; i++) {
		ctx->b[i] = (ctx->key[i/8] >> (i & 0x7)) & 0x1;
		ctx->s[i] = (ctx->iv[i/8] >> (i & 0x7)) & 0x1;
	}

	for(i = ctx->ivlen; i < ctx->keylen; i++) {
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
grain_set_key_and_iv(struct grain_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[12], const int ivlen)
{
	if((keylen <= GRAIN) && (keylen > 0))
		ctx->keylen = keylen * 8;
	else
		return -1;
	
	if((ivlen > 0) && (ivlen <= 12))
		ctx->ivlen = ivlen * 8;
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
//----------------------------------------------



// The stream algorithm HC128
//----------------------------------------------

// f1 and f2 function
#define F1(x)		(ROTR32(x,  7) ^ ROTR32(x, 18) ^ (x >>  3))
#define F2(x)		(ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))

// g1 and g2 function
#define G1(x, y, z, res) { 					\
	res = (ROTR32(x, 10) ^ ROTR32(z, 23)) + ROTR32(y, 8);	\
}

#define G2(x, y, z, res) {					\
	res = (ROTL32(x, 10) ^ ROTL32(z, 23)) + ROTL32(y, 8);	\
}

// h1 and h2 function
#define H1(ctx, x, res) {				\
	uint8_t a, b;					\
	a = (uint8_t)x;					\
	b = (uint8_t)(x >> 16);				\
	res = ctx->w[512 + a] + ctx->w[512 + 256 + b];	\
}

#define H2(ctx, x, res) {				\
	uint8_t a, b;					\
	a = (uint8_t)x;					\
	b = (uint8_t)(x >> 16);				\
	res = ctx->w[a] + ctx->w[256 + b];		\
}

// Update arrays P[512] and Q[512] (in this case - w[1024])
#define UPDATE_P(ctx, a, b, c, d, e, f) { 			\
	uint32_t res1, res2;					\
	G1(ctx->x[e], ctx->x[d], ctx->w[b], res1);		\
	H1(ctx, ctx->x[f], res2);				\
	ctx->w[a] = (ctx->w[a] + res1) ^ res2; 			\
	ctx->x[c] = ctx->w[a];					\
}

#define UPDATE_Q(ctx, a, b, c, d, e, f) {			\
	uint32_t res1, res2;					\
	G2(ctx->y[e], ctx->y[d], ctx->w[512+b], res1);		\
	H2(ctx, ctx->y[f], res2);				\
	ctx->w[512+a] = (ctx->w[512+a] + res1) ^ res2;		\
	ctx->y[c] = ctx->w[512+a];				\
}

// Generation of key sequence
#define GENERATE_P(ctx, a, b, c, d, e, f, res) {		\
	uint32_t res1, res2;					\
	G1(ctx->x[e], ctx->x[d], ctx->w[b], res1);		\
	H1(ctx, ctx->x[f], res2);				\
	ctx->w[a] += res1;					\
	ctx->x[c] = ctx->w[a];					\
	res = U32TO32((res2 ^ ctx->w[a]));			\
}

#define GENERATE_Q(ctx, a, b, c, d, e, f, res) {		\
	uint32_t res1, res2;					\
	G2(ctx->y[e], ctx->y[d], ctx->w[512+b], res1);		\
	H2(ctx, ctx->y[f], res2);				\
	ctx->w[512+a] += res1;					\
	ctx->y[c] = ctx->w[512+a];				\
	res = U32TO32((res2 ^ ctx->w[512+a]));			\
}

/* 
 * HC128 context
 * keylen - chiper key length in bytes
 * ivlen - vector initialization length in bytes
 * key - chiper key
 * iv - initialization vector
 * w - array with 1024 32-bit elements
 * x - array with 16 32-bit elements (for intermediate calculations)
 * y - array with 16 32-bit elements (for intermediate calculations)
 * counter - the counter system
*/
struct hc128_context {
	int keylen;
	int ivlen;
	uint8_t key[16];
	uint8_t iv[16];
	uint32_t w[1024];
	uint32_t x[16];
	uint32_t y[16];
	uint32_t counter;
};

// Allocates memory for the HC128 context
struct hc128_context *
hc128_context_new(void)
{
	struct hc128_context *ctx;
	ctx = (struct hc128_context *)malloc(sizeof(*ctx));

	if(ctx == NULL)
		return NULL;
	
	memset(ctx, 0, sizeof(*ctx));

	return ctx;
}

// Delete HC128 context
void
hc128_context_free(struct hc128_context **ctx)
{
	free(*ctx);
	*ctx = NULL;
}

// Function update array w[1024]
static void
hc128_setup_update(struct hc128_context *ctx)
{
	int i, a;
	
	for(i = 0; i < 64; i++) {

		a = ctx->counter & 0x1FF;
		
		if(ctx->counter < 512) {
			UPDATE_P(ctx, a +  0, a +  1,  0,  6, 13,  4);
			UPDATE_P(ctx, a +  1, a +  2,  1,  7, 14,  5);
			UPDATE_P(ctx, a +  2, a +  3,  2,  8, 15,  6);		
			UPDATE_P(ctx, a +  3, a +  4,  3,  9,  0,  7);
			UPDATE_P(ctx, a +  4, a +  5,  4, 10,  1,  8);
			UPDATE_P(ctx, a +  5, a +  6,  5, 11,  2,  9);
			UPDATE_P(ctx, a +  6, a +  7,  6, 12,  3, 10);
			UPDATE_P(ctx, a +  7, a +  8,  7, 13,  4, 11);
			UPDATE_P(ctx, a +  8, a +  9,  8, 14,  5, 12);
			UPDATE_P(ctx, a +  9, a + 10,  9, 15,  6, 13);
			UPDATE_P(ctx, a + 10, a + 11, 10,  0,  7, 14);
			UPDATE_P(ctx, a + 11, a + 12, 11,  1,  8, 15);
			UPDATE_P(ctx, a + 12, a + 13, 12,  2,  9,  0);
			UPDATE_P(ctx, a + 13, a + 14, 13,  3, 10,  1);
			UPDATE_P(ctx, a + 14, a + 15, 14,  4, 11,  2);
			UPDATE_P(ctx, a + 15, ((a + 16) & 0x1FF), 15,  5, 12,  3);
		}
		else {
			UPDATE_Q(ctx, a +  0, a +  1,  0,  6, 13,  4);
			UPDATE_Q(ctx, a +  1, a +  2,  1,  7, 14,  5);
			UPDATE_Q(ctx, a +  2, a +  3,  2,  8, 15,  6);
			UPDATE_Q(ctx, a +  3, a +  4,  3,  9,  0,  7);
			UPDATE_Q(ctx, a +  4, a +  5,  4, 10,  1,  8);
			UPDATE_Q(ctx, a +  5, a +  6,  5, 11,  2,  9);
			UPDATE_Q(ctx, a +  6, a +  7,  6, 12,  3, 10);
			UPDATE_Q(ctx, a +  7, a +  8,  7, 13,  4, 11);
			UPDATE_Q(ctx, a +  8, a +  9,  8, 14,  5, 12);
			UPDATE_Q(ctx, a +  9, a + 10,  9, 15,  6, 13);
			UPDATE_Q(ctx, a + 10, a + 11, 10,  0,  7, 14);
			UPDATE_Q(ctx, a + 11, a + 12, 11,  1,  8, 15);
			UPDATE_Q(ctx, a + 12, a + 13, 12,  2,  9,  0);
			UPDATE_Q(ctx, a + 13, a + 14, 13,  3, 10,  1);
			UPDATE_Q(ctx, a + 14, a + 15, 14,  4, 11,  2);
			UPDATE_Q(ctx, a + 15, ((a + 16) & 0x1FF), 15,  5, 12,  3);
		}
		
		ctx->counter = (ctx->counter + 16) & 0x3FF;
	}
}

// Function initialization process
// System is ready to generate keystream
static void
hc128_initialization_process(struct hc128_context *ctx)
{
	int i;

	for(i = 0; i < 8; i++) {
		ctx->w[i] = U8TO32_LITTLE(ctx->key + (i * 4) % 16);
		ctx->w[i + 8] = U8TO32_LITTLE(ctx->iv + (i * 4) % 16);
	}

	for(i = 0; i < (ctx->keylen >> 5); i++)
		ctx->w[i] = U8TO32_LITTLE(ctx->key + (i * 4));
	
	for(i = 16; i < (256 + 16); i++)
		ctx->w[i] = F2(ctx->w[i-2]) + ctx->w[i-7] + F1(ctx->w[i-15]) + ctx->w[i-16] + i;
	
	for(i = 0; i < 16; i++)
		ctx->w[i] = ctx->w[256 + i];
	
	for(i = 16; i < 1024; i++)
		ctx->w[i] = F2(ctx->w[i-2]) + ctx->w[i-7] + F1(ctx->w[i-15]) + ctx->w[i-16] + 256 + i;

	for(i = 0; i < 16; i++) {
		ctx->x[i] = ctx->w[496+i];
		ctx->y[i] = ctx->w[1008+i];
	}
	
	hc128_setup_update(ctx);
}

// Fill the HC128 context (key and iv)
// Return value: 0 (if all is well), -1 id all bad
int
hc128_set_key_and_iv(struct hc128_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[16], const int ivlen)
{
	if(keylen <= HC128)
		ctx->keylen = keylen;
	else
		return -1;
	
	if((ivlen > 0) && (ivlen <= 16))
		ctx->ivlen = ivlen;
	else
		return -1;
	
	memcpy(ctx->key, key, ctx->keylen);
	memcpy(ctx->iv, iv, ctx->ivlen);
	ctx->counter = 0;

	hc128_initialization_process(ctx);

	return 0;
}

// Function generate keystream
static void
hc128_generate_keystream(struct hc128_context *ctx, uint32_t *keystream)
{
	int a;
	a = ctx->counter & 0x1FF;

	if(ctx->counter < 512) {
		GENERATE_P(ctx, a +  0, a +  1,  0,  6, 13,  4, keystream[0]);
		GENERATE_P(ctx, a +  1, a +  2,  1,  7, 14,  5, keystream[1]);
		GENERATE_P(ctx, a +  2, a +  3,  2,  8, 15,  6, keystream[2]);
		GENERATE_P(ctx, a +  3, a +  4,  3,  9,  0,  7, keystream[3]);
		GENERATE_P(ctx, a +  4, a +  5,  4, 10,  1,  8, keystream[4]);
		GENERATE_P(ctx, a +  5, a +  6,  5, 11,  2,  9, keystream[5]);
		GENERATE_P(ctx, a +  6, a +  7,  6, 12,  3, 10, keystream[6]);
		GENERATE_P(ctx, a +  7, a +  8,  7, 13,  4, 11, keystream[7]);
		GENERATE_P(ctx, a +  8, a +  9,  8, 14,  5, 12, keystream[8]);
		GENERATE_P(ctx, a +  9, a + 10,  9, 15,  6, 13, keystream[9]);
		GENERATE_P(ctx, a + 10, a + 11, 10,  0,  7, 14, keystream[10]);
		GENERATE_P(ctx, a + 11, a + 12, 11,  1,  8, 15, keystream[11]);
		GENERATE_P(ctx, a + 12, a + 13, 12,  2,  9,  0, keystream[12]);
		GENERATE_P(ctx, a + 13, a + 14, 13,  3, 10,  1, keystream[13]);
		GENERATE_P(ctx, a + 14, a + 15, 14,  4, 11,  2, keystream[14]);
		GENERATE_P(ctx, a + 15, ((a + 16) & 0x1FF), 15,  5, 12,  3, keystream[15]);
	}
	else {
		GENERATE_Q(ctx, a +  0, a +  1,  0,  6, 13,  4, keystream[0]);
		GENERATE_Q(ctx, a +  1, a +  2,  1,  7, 14,  5, keystream[1]);
		GENERATE_Q(ctx, a +  2, a +  3,  2,  8, 15,  6, keystream[2]);
		GENERATE_Q(ctx, a +  3, a +  4,  3,  9,  0,  7, keystream[3]);
		GENERATE_Q(ctx, a +  4, a +  5,  4, 10,  1,  8, keystream[4]);
		GENERATE_Q(ctx, a +  5, a +  6,  5, 11,  2,  9, keystream[5]);
		GENERATE_Q(ctx, a +  6, a +  7,  6, 12,  3, 10, keystream[6]);
		GENERATE_Q(ctx, a +  7, a +  8,  7, 13,  4, 11, keystream[7]);
		GENERATE_Q(ctx, a +  8, a +  9,  8, 14,  5, 12, keystream[8]);
		GENERATE_Q(ctx, a +  9, a + 10,  9, 15,  6, 13, keystream[9]);
		GENERATE_Q(ctx, a + 10, a + 11, 10,  0,  7, 14, keystream[10]);
		GENERATE_Q(ctx, a + 11, a + 12, 11,  1,  8, 15, keystream[11]);
		GENERATE_Q(ctx, a + 12, a + 13, 12,  2,  9,  0, keystream[12]);
		GENERATE_Q(ctx, a + 13, a + 14, 13,  3, 10,  1, keystream[13]);
		GENERATE_Q(ctx, a + 14, a + 15, 14,  4, 11,  2, keystream[14]);
		GENERATE_Q(ctx, a + 15, ((a + 16) & 0x1FF), 15,  5, 12,  3, keystream[15]);
	}
	
	ctx->counter = (ctx->counter + 16) & 0x3ff;
}

/*
 * HC128 encrypt algorithm.
 * ctx - pointer on HC128 context
 * buf - pointer on buffer data
 * buflen - length the data buffer
 * out - pointer on output array
*/
void
hc128_encrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	uint32_t keystream[16];
	uint32_t i;

	for(; buflen >= 64; buflen -= 64, buf += 64, out += 64) {
		hc128_generate_keystream(ctx, keystream);

		*(uint32_t *)(out +  0) = *(uint32_t *)(buf +  0) ^ keystream[ 0];
		*(uint32_t *)(out +  4) = *(uint32_t *)(buf +  4) ^ keystream[ 1];
		*(uint32_t *)(out +  8) = *(uint32_t *)(buf +  8) ^ keystream[ 2];
		*(uint32_t *)(out + 12) = *(uint32_t *)(buf + 12) ^ keystream[ 3];
		*(uint32_t *)(out + 16) = *(uint32_t *)(buf + 16) ^ keystream[ 4];
		*(uint32_t *)(out + 20) = *(uint32_t *)(buf + 20) ^ keystream[ 5];
		*(uint32_t *)(out + 24) = *(uint32_t *)(buf + 24) ^ keystream[ 6];
		*(uint32_t *)(out + 28) = *(uint32_t *)(buf + 28) ^ keystream[ 7];
		*(uint32_t *)(out + 32) = *(uint32_t *)(buf + 32) ^ keystream[ 8];
		*(uint32_t *)(out + 36) = *(uint32_t *)(buf + 36) ^ keystream[ 9];
		*(uint32_t *)(out + 40) = *(uint32_t *)(buf + 40) ^ keystream[10];
		*(uint32_t *)(out + 44) = *(uint32_t *)(buf + 44) ^ keystream[11];
		*(uint32_t *)(out + 48) = *(uint32_t *)(buf + 48) ^ keystream[12];
		*(uint32_t *)(out + 52) = *(uint32_t *)(buf + 52) ^ keystream[13];
		*(uint32_t *)(out + 56) = *(uint32_t *)(buf + 56) ^ keystream[14];
		*(uint32_t *)(out + 60) = *(uint32_t *)(buf + 60) ^ keystream[15];
	}
	
	if(buflen) {
		hc128_generate_keystream(ctx, keystream);
		
		for(i = 0; i < buflen; i++)
			out[i] = buf[i] ^ ((uint8_t *)keystream)[i];
	}
}

// HC128 decrypt function. See hc128_encrypt
void
hc128_decrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	hc128_encrypt(ctx, buf, buflen, out);
}

// Test vectors print
void
hc128_test_vectors(struct hc128_context *ctx)
{
	uint32_t keystream[16];
	int i;
	
	hc128_generate_keystream(ctx, keystream);

	printf("\nTest vectors for the HC-128\n");

	printf("\nKey:       ");

	for(i = 0; i < 16; i++)
		printf("%02x ", ctx->key[i]);

	printf("\nIV:        ");

	for(i = 0; i < 16; i++)
		printf("%02x ", ctx->iv[i]);
	
	printf("\nKeystream: ");

	for(i = 0; i < 16; i++) {
		PRINT_U32TO32((keystream[i]));
	}
	
	printf("\n\n");
}
//----------------------------------------------



// The stream algorithm MICKEY 2.0
//----------------------------------------------

// Feedback mask associated with the register R
uint32_t R_MASK[4] = { 0x1279327B, 0xB5546660,
		       0xDF87818F, 0x00000003 };

// Input mask associated with register S
uint32_t COMP0[4] = { 0x6AA97A30, 0x7942A809, 
		      0x057EBFEA, 0x00000006 };

// Second input mask associated with register S
uint32_t COMP1[4] = { 0xDD629E9A, 0xE3A21D63, 
		      0x91C23DD7, 0x00000001 };

// Feedback mask associated with the register S for clock control_bit = 0
uint32_t S_MASK0[4] = { 0x9FFA7FAF, 0xAF4A9381,
			0x9CEC5802, 0x00000001 };

// Feedback mask associated with the register S for clock control_bit = 1
uint32_t S_MASK1[4] = { 0x4C8CB877, 0x4911B063,
			0x40FBC52B, 0x00000008 };
/*
 * MICKEY 2.0 context
 * keylen - chiper key length in bytes
 * ivlen - vector initialization in bytes
 * key - chiper key 
 * iv - initialization vector
 * r - register r
 * s - register s
*/
struct mickey_context {
	int keylen;
	int ivlen;
	uint8_t key[10];
	uint8_t iv[10];
	uint32_t r[4];
	uint32_t s[4];
};

// Allocates memory for the mickey_context
struct mickey_context *
mickey_context_new(void)
{
	struct mickey_context *ctx;
	ctx = (struct mickey_context *)malloc(sizeof(*ctx));

	if(ctx == NULL)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));

	return ctx;
}

// Delete mickey_context
void
mickey_context_free(struct mickey_context **ctx)
{
	free(*ctx);
	*ctx = NULL;
}

// Function clocking the register R
static void
CLOCK_R(struct mickey_context *ctx, const uint8_t input_bit_r, const uint8_t control_bit_r)
{
	int feedback_bit, carry0, carry1, carry2;

	feedback_bit = ((ctx->r[3] >> 3) & 1) ^ input_bit_r;
	carry0 = (ctx->r[0] >> 31) & 1;
	carry1 = (ctx->r[1] >> 31) & 1;
	carry2 = (ctx->r[2] >> 31) & 1;

	if(control_bit_r) {
		ctx->r[0] ^= (ctx->r[0] << 1);
		ctx->r[1] ^= (ctx->r[1] << 1) ^ carry0;
		ctx->r[2] ^= (ctx->r[2] << 1) ^ carry1;
		ctx->r[3] ^= (ctx->r[3] << 1) ^ carry2;
	}
	else {
		ctx->r[0] = (ctx->r[0] << 1);
		ctx->r[1] = (ctx->r[1] << 1) ^ carry0;
		ctx->r[2] = (ctx->r[2] << 1) ^ carry1;
		ctx->r[3] = (ctx->r[3] << 1) ^ carry2;
	}

	if(feedback_bit) {
		ctx->r[0] ^= R_MASK[0];
		ctx->r[1] ^= R_MASK[1];
		ctx->r[2] ^= R_MASK[2];
		ctx->r[3] ^= R_MASK[3];
	}
}

// Function clocking the register S
static void
CLOCK_S(struct mickey_context *ctx, const uint8_t input_bit_s, const uint8_t control_bit_s)
{
	int feedback_bit, carry0, carry1, carry2;

	feedback_bit = ((ctx->s[3] >> 3) & 1) ^ input_bit_s;
	carry0 = (ctx->s[0] >> 31) & 1;
	carry1 = (ctx->s[1] >> 31) & 1;
	carry2 = (ctx->s[2] >> 31) & 1;

	ctx->s[0] = (ctx->s[0] << 1) ^ ((ctx->s[0] ^ COMP0[0]) & ((ctx->s[0] >> 1) ^ (ctx->s[1] << 31) ^ COMP1[0]) & 0xFFFFFFFE);
	ctx->s[1] = (ctx->s[1] << 1) ^ ((ctx->s[1] ^ COMP0[1]) & ((ctx->s[1] >> 1) ^ (ctx->s[2] << 31) ^ COMP1[1])) ^ carry0;
	ctx->s[2] = (ctx->s[2] << 1) ^ ((ctx->s[2] ^ COMP0[2]) & ((ctx->s[2] >> 1) ^ (ctx->s[3] << 31) ^ COMP1[2])) ^ carry1;
	ctx->s[3] = (ctx->s[3] << 1) ^ ((ctx->s[3] ^ COMP0[3]) & ((ctx->s[3] >> 1) ^ COMP1[3]) & 0x7) ^ carry2;

	if(feedback_bit) {
		if(control_bit_s) {
			ctx->s[0] ^= S_MASK1[0];
			ctx->s[1] ^= S_MASK1[1];
			ctx->s[2] ^= S_MASK1[2];
			ctx->s[3] ^= S_MASK1[3];
		}
		else {
			ctx->s[0] ^= S_MASK0[0];
			ctx->s[1] ^= S_MASK0[1];
			ctx->s[2] ^= S_MASK0[2];
			ctx->s[3] ^= S_MASK0[3];
		}
	}
}

// Function clocking the overall generator
static void
CLOCK_KG(struct mickey_context *ctx, const uint8_t mixing, const uint8_t input_bit)
{
	int control_bit_r, control_bit_s;

	control_bit_r = ((ctx->s[1] >> 2) ^ (ctx->r[2] >> 3)) & 1;
	control_bit_s = ((ctx->r[1] >> 1) ^ (ctx->s[2] >> 3)) & 1;

	if(mixing)
		CLOCK_R(ctx, ((ctx->s[1] >> 18) & 1) ^ input_bit, control_bit_r);
	else
		CLOCK_R(ctx, input_bit, control_bit_r);
	
	CLOCK_S(ctx, input_bit, control_bit_s);
}

// Function key loading and initialization (filling registers R and S)
static void
mickey_key_setup(struct mickey_context *ctx)
{
	uint8_t input_bit;
	int i;

	memset(ctx->r, 0, sizeof(ctx->r));
	memset(ctx->s, 0, sizeof(ctx->s));
	
	for(i = 0; i < (ctx->ivlen * 8); i++) {
		input_bit = (ctx->iv[i/8] >> (7 - (i & 0x7))) & 1;
		CLOCK_KG(ctx, 1, input_bit);
	}
	
	for(i = 0; i < 80; i++) {
		input_bit = (ctx->key[i/8] >> (7 - (i & 0x7))) & 1;
		CLOCK_KG(ctx, 1, input_bit);
	}
	
	for(i = 0; i < 100; i++)
		CLOCK_KG(ctx, 1, 0);
}

// Fill the mickey_context (key and iv)
// Return value: 0 (if all is well), -1 (is all bad)
int
mickey_set_key_and_iv(struct mickey_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[10], const int ivlen)
{
	if((keylen > 0) && (keylen <= MICKEY))
		
		ctx->keylen = keylen;
	else
		return -1;
	
	if((ivlen > 0) && (ivlen <= 10))
		ctx->ivlen = ivlen;
	else
		return -1;
	
	memcpy(ctx->key, key, keylen);
	memcpy(ctx->iv, iv, 10);

	mickey_key_setup(ctx);

	return 0;
}

/*
 * MICKEY 2.0 encrypt function 
 * ctx - pointer on mickey_context  
 * buf - pointer on buffer data 
 * buflen - length the data buffer
 * out - pointer on output 
*/
void
mickey_encrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out)
{
	uint32_t i, j;
	int keystream;

	for(i = 0; i < buflen; i++) {
		out[i] = buf[i];

		for(j = 0; j < 8; j++) {
			keystream = ((ctx->r[0] ^ ctx->s[0]) & 1) << (7-j);
			CLOCK_KG(ctx, 0, 0);
			out[i] ^= keystream;
		}
	}
}

// MICKEY 2.0 decrypt function. See mickey_encrypt
void
mickey_decrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out)
{
	mickey_encrypt(ctx, buf, buflen, out);
}

// Test vectors print
void
mickey_test_vectors(struct mickey_context *ctx)
{
	uint32_t i, j;
	uint8_t keystream[16];

	for(i = 0; i < 16; i++) {
		
		keystream[i] = 0;

		for(j = 0; j < 8; j++) {
			keystream[i] ^= ((ctx->r[0] ^ ctx->s[0]) & 1) << (7-j);
			CLOCK_KG(ctx, 0, 0);
		}
	}
	
	printf("Tests vector for the Mickey:\n");
	
	printf("\nKey:       ");

	for(i = 0; i < 10; i++)
		printf("%02x ", ctx->key[i]);
	
	printf("\nIV:        ");

	for(i = 0; i < 10; i++)
		printf("%02x ", ctx->iv[i]);
	
	printf("\nKeystream: ");

	for(i = 0; i < 16; i++)
		printf("%02x ", keystream[i]);
	
	printf("\n\n");
}
//----------------------------------------------



// The stream algorithm RABBIT
//----------------------------------------------

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

/* RABBIT-128 context
 * keylen - chiper key length in bytes
 * ivlen - vector initializaton length in bytes
 * key - chiper key
 * iv - initialization vector
 * x - the state variables
 * c - the counter system  
 * carry - 513 bit, the internal state
*/
struct rabbit_context {
	int keylen;
	int ivlen;
	uint8_t key[16];
	uint8_t iv[8];
	uint32_t x[8];
	uint32_t c[8];
	uint32_t carry;
};

// Allocates memory for the RABBIT context
struct rabbit_context *
rabbit_context_new(void)
{
	struct rabbit_context *ctx;
	ctx = (struct rabbit_context *)malloc(sizeof(*ctx));

	if(ctx == NULL)
		return NULL;
	
	memset(ctx, 0, sizeof(*ctx));
	
	return ctx;
}

// Delete RABBIT context
void
rabbit_context_free(struct rabbit_context **ctx)
{
	free(*ctx);
	*ctx = NULL;
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
 * RABBIT encrypt algorithm.
 * ctx - pointer on RABBIT context
 * buf - pointer on buffer data
 * buflen - length the data buffer
 * out - pointer on output array
*/
void
rabbit_encrypt(struct rabbit_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
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

// RABBIT decrypt function. See rabbit_encrypt
void
rabbit_decrypt(struct rabbit_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	rabbit_encrypt(ctx, buf, buflen, out);
}

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
//----------------------------------------------



// The stream algorithm SALSA
//----------------------------------------------

/* 
 * Salsa context
 * keylen - chiper key length in bytes
 * ivlen - vector initialization length in bytes
 * key - chiper key
 * iv - 16-byte array with a unique number. 8 bytes are filled by the user
 * x - intermediate array
*/
struct salsa_context {
	int keylen;
	int ivlen;
	uint8_t key[SALSA32];
	uint8_t iv[16];
	uint32_t x[16];
};

// Allocates memory for the salsa context
struct salsa_context * 
salsa_context_new(void)
{
	struct salsa_context *ctx;
	ctx = (struct salsa_context *)malloc(sizeof(*ctx));

	if(ctx == NULL)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	
	return ctx;
}

// Delete salsa context
void
salsa_context_free(struct salsa_context **ctx)
{
	free(*ctx);
	*ctx = NULL;
}

// Fill the salsa context (key and iv)
// Return value: 0 (if all is well), -1 (if all bad)
int
salsa_set_key_and_iv(struct salsa_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[8], const int ivlen)
{
	int i, j;
	uint8_t *expand;

	uint8_t key_expand_16 [] = {
		'e', 'x', 'p', 'a',
		'n', 'd', ' ', '1',
		'6', '-', 'b', 'y',
		't', 'e', ' ', 'k'
	};

	uint8_t key_expand_32 [] = {
		'e', 'x', 'p', 'a',
		'n', 'd', ' ', '3',
		'2', '-', 'b', 'y',
		't', 'e', ' ', 'k'
	};

	if(keylen == SALSA32) {
		ctx->keylen = SALSA32;
		expand = (uint8_t *)key_expand_32;
		j = 4;
	}
	else if((keylen < SALSA32) && (keylen > 0)){
		ctx->keylen = keylen;
		expand = (uint8_t *)key_expand_16;
		j = 0;
	}
	else
	     	return -1;

	if((ivlen > 0) && (ivlen <= 8))
		ctx->ivlen = ivlen;
	else
		return -1;

	memcpy(ctx->key, key, ctx->keylen);

	// Fill the iv user data: iv[0] - iv[7].
	memcpy(ctx->iv, iv, ctx->ivlen);
	
	// Fill the iv: iv[8] - iv[15].
	for(i = 8; i < 16; i++)
		ctx->iv[i] = 0;
	
	for(i = 0; i < 4; i++) {
		ctx->x[i *  5] = U8TO32_LITTLE((expand + (i * 4)));
		ctx->x[i +  1] = U8TO32_LITTLE((ctx->key + (i * 4)));
		ctx->x[i +  6] = U8TO32_LITTLE((ctx->iv + (i * 4)));
		ctx->x[i + 11] = U8TO32_LITTLE((ctx->key + ((j + i) * 4)));
	}

	return 0;
}

// Salsa hash function
static void
salsa20(struct salsa_context *ctx, uint32_t *keystream)
{
	uint32_t z[16];
	int i;

	for(i = 0; i < 16; i++)
		z[i] = ctx->x[i];

	for(i = 0; i < 10; i++) {
		z[ 4] ^= ROTL32((z[ 0] + z[12]), 7);
		z[ 8] ^= ROTL32((z[ 4] + z[ 0]), 9);
		z[12] ^= ROTL32((z[ 8] + z[ 4]), 13);
		z[ 0] ^= ROTL32((z[12] + z[ 8]), 18);

		z[ 9] ^= ROTL32((z[ 5] + z[ 1]), 7);
		z[13] ^= ROTL32((z[ 9] + z[ 5]), 9);
		z[ 1] ^= ROTL32((z[13] + z[ 9]), 13);
		z[ 5] ^= ROTL32((z[ 1] + z[13]), 18);

		z[14] ^= ROTL32((z[10] + z[ 6]), 7);
		z[ 2] ^= ROTL32((z[14] + z[10]), 9);
		z[ 6] ^= ROTL32((z[ 2] + z[14]), 13);
		z[10] ^= ROTL32((z[ 6] + z[ 2]), 18);

		z[ 3] ^= ROTL32((z[15] + z[11]), 7);
		z[ 7] ^= ROTL32((z[ 3] + z[15]), 9);
		z[11] ^= ROTL32((z[ 7] + z[ 3]), 13);
		z[15] ^= ROTL32((z[11] + z[ 7]), 18);
	
		z[ 1] ^= ROTL32((z[ 0] + z[ 3]), 7);
		z[ 2] ^= ROTL32((z[ 1] + z[ 0]), 9);
		z[ 3] ^= ROTL32((z[ 2] + z[ 1]), 13);
		z[ 0] ^= ROTL32((z[ 3] + z[ 2]), 18);

		z[ 6] ^= ROTL32((z[ 5] + z[ 4]), 7);
		z[ 7] ^= ROTL32((z[ 6] + z[ 5]), 9);
		z[ 4] ^= ROTL32((z[ 7] + z[ 6]), 13);
		z[ 5] ^= ROTL32((z[ 4] + z[ 7]), 18);
	
		z[11] ^= ROTL32((z[10] + z[ 9]), 7);
		z[ 8] ^= ROTL32((z[11] + z[10]), 9);
		z[ 9] ^= ROTL32((z[ 8] + z[11]), 13);
		z[10] ^= ROTL32((z[ 9] + z[ 8]), 18);

		z[12] ^= ROTL32((z[15] + z[14]), 7);
		z[13] ^= ROTL32((z[12] + z[15]), 9);
		z[14] ^= ROTL32((z[13] + z[12]), 13);
		z[15] ^= ROTL32((z[14] + z[13]), 18);
	}
	
	for(i = 0; i < 16; i++)
		keystream[i] = U32TO32(z[i] + ctx->x[i]);
}

/* 
 * Salsa encrypt algorithm.
 * ctx - pointer on salsa context
 * buf - pointer on buffer data
 * buflen - length the data buffer
*/
void
salsa_encrypt(struct salsa_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	uint32_t keystream[16];
	uint32_t i;
	
	for(; buflen >= 64; buflen -= 64, buf += 64, out += 64) {
		salsa20(ctx, keystream);
		
		ctx->x[8] += 1;

		if(!ctx->x[8])
			ctx->x[9] += 1;

		*(uint32_t *)(out +  0) = *(uint32_t *)(buf +  0) ^ keystream[ 0];
		*(uint32_t *)(out +  4) = *(uint32_t *)(buf +  4) ^ keystream[ 1];
		*(uint32_t *)(out +  8) = *(uint32_t *)(buf +  8) ^ keystream[ 2];
		*(uint32_t *)(out + 12) = *(uint32_t *)(buf + 12) ^ keystream[ 3];
		*(uint32_t *)(out + 16) = *(uint32_t *)(buf + 16) ^ keystream[ 4];
		*(uint32_t *)(out + 20) = *(uint32_t *)(buf + 20) ^ keystream[ 5];
		*(uint32_t *)(out + 24) = *(uint32_t *)(buf + 24) ^ keystream[ 6];
		*(uint32_t *)(out + 28) = *(uint32_t *)(buf + 28) ^ keystream[ 7];
		*(uint32_t *)(out + 32) = *(uint32_t *)(buf + 32) ^ keystream[ 8];
		*(uint32_t *)(out + 36) = *(uint32_t *)(buf + 36) ^ keystream[ 9];
		*(uint32_t *)(out + 40) = *(uint32_t *)(buf + 40) ^ keystream[10];
		*(uint32_t *)(out + 44) = *(uint32_t *)(buf + 44) ^ keystream[11];
		*(uint32_t *)(out + 48) = *(uint32_t *)(buf + 48) ^ keystream[12];
		*(uint32_t *)(out + 52) = *(uint32_t *)(buf + 52) ^ keystream[13];
		*(uint32_t *)(out + 56) = *(uint32_t *)(buf + 56) ^ keystream[14];
		*(uint32_t *)(out + 60) = *(uint32_t *)(buf + 60) ^ keystream[15];
	}

	if(buflen > 0) {
		salsa20(ctx, keystream);

		ctx->x[8] += 1;

		if(!ctx->x[8])
			ctx->x[9] += 1;

		for(i = 0; i < buflen; i++)
			out[i] = buf[i] ^ ((uint8_t *)keystream)[i];
	}

}

// Salsa decrypt function. See salsa_encrypt
void
salsa_decrypt(struct salsa_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	salsa_encrypt(ctx, buf, buflen, out);
}

void
salsa_test_vectors(struct salsa_context *ctx)
{
	uint32_t keystream[16];
	int i;

	salsa20(ctx, keystream);

	printf("\nTest vectors for the Salsa20 64 bytes:\n");

	printf("\nKey:       ");

	for(i = 0; i < 32; i++)
		printf("%02x ", ctx->key[i]);
	
	printf("\nIV:        ");
	
	for(i = 0; i < 16; i++)
		printf("%02x ", ctx->iv[i]);
	
	printf("\nKeystream: ");

	for(i = 0; i < 16; i++)
		PRINT_U32TO32(keystream[i]);
	
	printf("\n\n");
}
//----------------------------------------------



// The stream algorithm SOSEMANUK
//----------------------------------------------

// Serpent S-boxes, implemented in bitslice mode.
// These circuits have been published by Dag Arne Osvik ("Speeding up Serpent"). 
// Published in the 3rd AES Candidate Conference.

#define S0(r0, r1, r2, r3, r4) {	\
	r3 ^= r0; r4  = r1;		\
	r1 &= r3; r4 ^= r2;		\
	r1 ^= r0; r0 |= r3;		\
	r0 ^= r4; r4 ^= r3;		\
	r3 ^= r2; r2 |= r1;		\
	r2 ^= r4; r4 =~ r4;		\
	r4 |= r1; r1 ^= r3;		\
	r1 ^= r4; r3 |= r0;		\
	r1 ^= r3; r4 ^= r3;		\
}

#define S1(r0, r1, r2, r3, r4) {	\
	r0 =~ r0; r2 =~ r2;		\
	r4  = r0; r0 &= r1;		\
	r2 ^= r0; r0 |= r3;		\
	r3 ^= r2; r1 ^= r0;		\
	r0 ^= r4; r4 |= r1;		\
	r1 ^= r3; r2 |= r0;		\
	r2 &= r4; r0 ^= r1;		\
	r1 &= r2;			\
	r1 ^= r0; r0 &= r2;		\
	r0 ^= r4;			\
}

#define S2(r0, r1, r2, r3, r4) {	\
	r4  = r0; r0 &= r2;		\
	r0 ^= r3; r2 ^= r1;		\
	r2 ^= r0; r3 |= r4;		\
	r3 ^= r1; r4 ^= r2;		\
	r1  = r3; r3 |= r4;		\
	r3 ^= r0; r0 &= r1;		\
	r4 ^= r0; r1 ^= r3;		\
	r1 ^= r4; r4 =~ r4;		\
}

#define S3(r0, r1, r2, r3, r4) {	\
	r4  = r0; r0 |= r3;		\
	r3 ^= r1; r1 &= r4;		\
	r4 ^= r2; r2 ^= r3;		\
	r3 &= r0; r4 |= r1;		\
	r3 ^= r4; r0 ^= r1;		\
	r4 &= r0; r1 ^= r3;		\
	r4 ^= r2; r1 |= r0;		\
	r1 ^= r2; r0 ^= r3;		\
	r2  = r1; r1 |= r3;		\
	r1 ^= r0;			\
}

#define S4(r0, r1, r2, r3, r4) {	\
	r1 ^= r3; r3 =~ r3;		\
	r2 ^= r3; r3 ^= r0;		\
	r4  = r1; r1 &= r3;		\
	r1 ^= r2; r4 ^= r3;		\
	r0 ^= r4; r2 &= r4;		\
	r2 ^= r0; r0 &= r1;		\
	r3 ^= r0; r4 |= r1;		\
	r4 ^= r0; r0 |= r3;		\
	r0 ^= r2; r2 &= r3;		\
	r0 =~ r0; r4 ^= r2;		\
}

#define S5(r0, r1, r2, r3, r4) {	\
	r0 ^= r1; r1 ^= r3;		\
	r3 =~ r3; r4  = r1;		\
	r1 &= r0; r2 ^= r3;		\
	r1 ^= r2; r2 |= r4;		\
	r4 ^= r3; r3 &= r1;		\
	r3 ^= r0; r4 ^= r1;		\
	r4 ^= r2; r2 ^= r0;		\
	r0 &= r3; r2 =~ r2;		\
	r0 ^= r4; r4 |= r3;		\
	r2 ^= r4;			\
}

#define S6(r0, r1, r2, r3, r4) {	\
	r2 =~ r2; r4  = r3;		\
	r3 &= r0; r0 ^= r4;		\
	r3 ^= r2; r2 |= r4;		\
	r1 ^= r3; r2 ^= r0;		\
	r0 |= r1; r2 ^= r1;		\
	r4 ^= r0; r0 |= r3;		\
	r0 ^= r2; r4 ^= r3;		\
	r4 ^= r0; r3 =~ r3;		\
	r2 &= r4; r2 ^= r3;		\
}

#define S7(r0, r1, r2, r3, r4) {	\
	r4  = r1; r1 |= r2;		\
	r1 ^= r3; r4 ^= r2;		\
	r2 ^= r1; r3 |= r4;		\
	r3 &= r0; r4 ^= r2;		\
	r3 ^= r1; r1 |= r4;		\
	r1 ^= r0; r0 |= r4;		\
	r0 ^= r2; r1 ^= r4;		\
	r2 ^= r1; r1 &= r0;		\
	r1 ^= r4; r2 =~ r2;		\
	r2 |= r0; r4 ^= r2;		\
}

// This key schedule is actually a truncated Serpent key schedule
#define SKS(S, a, b, c, d, x0, x1, x2, x3) {	\
	uint32_t r0, r1, r2, r3, r4;		\
	r0 = a;					\
	r1 = b;					\
	r2 = c;					\
	r3 = d;					\
						\
	S(r0, r1, r2, r3, r4);			\
						\
	ctx->sk[i++] = r ## x0;			\
	ctx->sk[i++] = r ## x1;			\
	ctx->sk[i++] = r ## x2;			\
	ctx->sk[i++] = r ## x3;			\
}

#define SKS0	SKS(S0, w4, w5, w6, w7, 1, 4, 2, 0)
#define SKS1	SKS(S1, w0, w1, w2, w3, 2, 0, 3, 1)
#define SKS2	SKS(S2, w4, w5, w6, w7, 2, 3, 1, 4)
#define SKS3	SKS(S3, w0, w1, w2, w3, 1, 2, 3, 4)
#define SKS4	SKS(S4, w4, w5, w6, w7, 1, 4, 0, 3)
#define SKS5	SKS(S5, w0, w1, w2, w3, 1, 3, 0, 2)
#define SKS6	SKS(S6, w4, w5, w6, w7, 0, 1, 4, 2)
#define SKS7	SKS(S7, w0, w1, w2, w3, 4, 3, 1, 0)

#define WUP(a, b, c, d, cc) {					\
	uint32_t tt;						\
	tt = a ^ b ^ c ^ d ^ (0x9E3779B9 ^ ((uint32_t)cc));	\
	a = ROTL32(tt, 11);					\
}

#define WUP0(cc) {			\
	WUP(w0, w3, w5, w7, cc);	\
	WUP(w1, w4, w6, w0, cc + 1);	\
	WUP(w2, w5, w7, w1, cc + 2);	\
	WUP(w3, w6, w0, w2, cc + 3);	\
}

#define WUP1(cc) {			\
	WUP(w4, w7, w1, w3, cc);	\
	WUP(w5, w0, w2, w4, cc + 1);	\
	WUP(w6, w1, w3, w5, cc + 2);	\
	WUP(w7, w2, w4, w6, cc + 3);	\
}

// The Serpent key addition step
#define KA(zc, x0, x1, x2, x3) {	\
	x0 ^= ctx->sk[zc];		\
	x1 ^= ctx->sk[zc + 1];		\
	x2 ^= ctx->sk[zc + 2];		\
	x3 ^= ctx->sk[zc + 3];		\
}

// The Serpent linear transform
#define SERPENT_LT(x0, x1, x2, x3) {	\
	x0 = ROTL32(x0, 13);		\
	x2 = ROTL32(x2, 3);		\
	x1 = x1 ^ x0 ^ x2;		\
	x3 = x3 ^ x2 ^ (x0 << 3);	\
	x1 = ROTL32(x1, 1);		\
	x3 = ROTL32(x3, 7);		\
	x0 = x0 ^ x1 ^ x3;		\
	x2 = x2 ^ x3 ^ (x1 << 7);	\
	x0 = ROTL32(x0, 5);		\
	x2 = ROTL32(x2, 22);		\
}

/* 
 * One Serpent round
 * zc - current subkey counter
 * S - S-box macro for this round
 * i0 - i4 - input register number
 * o0 - o3 - output register number
*/
#define FSS(zc, S, i0, i1, i2, i3, i4, o0, o1, o2, o3) {	\
	KA(zc, r ## i0, r ## i1, r ## i2, r ## i3);		\
	S(r ## i0, r ## i1, r ## i2, r ## i3, r ## i4);		\
	SERPENT_LT(r ## o0, r ## o1, r ## o2, r ## o3);		\
}

// Last Serpent round. Keep the linear transformation for that last round
#define FSF(zc, S, i0, i1, i2, i3, i4, o0, o1, o2, o3) {	\
	KA(zc, r ## i0, r ## i1, r ## i2, r ## i3);		\
	S(r ## i0, r ## i1, r ## i2, r ## i3, r ## i4);		\
	SERPENT_LT(r ## o0, r ## o1, r ## o2, r ## o3);		\
	KA(zc + 4, r ## o0, r ## o1, r ## o2, r ## o3);		\
}

// This macro computes the special multiplexer, winch chooses between  "x" and "x xor y"
#define XMUX(c, x, y)	((c & 0x1) ? (x ^ y) : x)

// Multiplication (alpha * x) and (1/alpha * x)
#define MUL_A(x)	((x << 8) ^ mul_a[x >> 24])
#define MUL_G(x)	(((x) >> 8) ^ mul_ia[x & 0xFF])

// Updates the finite state machine
#define FSM(x1, x3) {				\
	uint32_t tt, or1;			\
	tt = XMUX(r1, s ## x1, s ## x3);	\
	or1 = r1;				\
	r1 = r2 + tt;				\
	tt = or1 * 0x54655307;			\
	r2 = ROTL32(tt, 7);			\
}

// Updates the shift registres. Value stored in "dd" and "ee"
#define LRU(x0, x2, x4, dd, ee) {				\
	dd = s ## x0;						\
	s ## x0 = MUL_A(s ## x0) ^ MUL_G(s ## x2) ^ s ## x4;	\
	ee = (s ## x4 + r1) ^ r2;				\
}

// Computes one internal round
#define STEP(x0, x1, x2, x3, x4, dd, ee) {	\
	FSM(x1, x3);				\
	LRU(x0, x2, x4, dd, ee);		\
}

// Entry keystream
#define SRD(S, x0, x1, x2, x3, i) {		\
	S(u0, u1, u2, u3, u4);			\
	keystream[i] = U32TO32(((u ## x0) ^ v0));		\
	keystream[i + 1] = U32TO32(((u ## x1) ^ v1));	\
	keystream[i + 2] = U32TO32(((u ## x2) ^ v2));	\
	keystream[i + 3] = U32TO32(((u ## x3) ^ v3));	\
}

// Multiplication by alpha: alpha * x = (x << 8) ^ mul_a[x >> 24]
uint32_t mul_a[] = {
	0x00000000, 0xE19FCF13, 0x6B973726, 0x8A08F835,
	0xD6876E4C, 0x3718A15F, 0xBD10596A, 0x5C8F9679,
	0x05A7DC98, 0xE438138B, 0x6E30EBBE, 0x8FAF24AD,
	0xD320B2D4, 0x32BF7DC7, 0xB8B785F2, 0x59284AE1,
	0x0AE71199, 0xEB78DE8A, 0x617026BF, 0x80EFE9AC,
	0xDC607FD5, 0x3DFFB0C6, 0xB7F748F3, 0x566887E0,
	0x0F40CD01, 0xEEDF0212, 0x64D7FA27, 0x85483534,
	0xD9C7A34D, 0x38586C5E, 0xB250946B, 0x53CF5B78,
	0x1467229B, 0xF5F8ED88, 0x7FF015BD, 0x9E6FDAAE,
	0xC2E04CD7, 0x237F83C4, 0xA9777BF1, 0x48E8B4E2,
	0x11C0FE03, 0xF05F3110, 0x7A57C925, 0x9BC80636,
	0xC747904F, 0x26D85F5C, 0xACD0A769, 0x4D4F687A,
	0x1E803302, 0xFF1FFC11, 0x75170424, 0x9488CB37,
	0xC8075D4E, 0x2998925D, 0xA3906A68, 0x420FA57B,
	0x1B27EF9A, 0xFAB82089, 0x70B0D8BC, 0x912F17AF,
	0xCDA081D6, 0x2C3F4EC5, 0xA637B6F0, 0x47A879E3,
	0x28CE449F, 0xC9518B8C, 0x435973B9, 0xA2C6BCAA,
	0xFE492AD3, 0x1FD6E5C0, 0x95DE1DF5, 0x7441D2E6,
	0x2D699807, 0xCCF65714, 0x46FEAF21, 0xA7616032,
	0xFBEEF64B, 0x1A713958, 0x9079C16D, 0x71E60E7E,
	0x22295506, 0xC3B69A15, 0x49BE6220, 0xA821AD33,
	0xF4AE3B4A, 0x1531F459, 0x9F390C6C, 0x7EA6C37F,
	0x278E899E, 0xC611468D, 0x4C19BEB8, 0xAD8671AB,
	0xF109E7D2, 0x109628C1, 0x9A9ED0F4, 0x7B011FE7,
	0x3CA96604, 0xDD36A917, 0x573E5122, 0xB6A19E31,
	0xEA2E0848, 0x0BB1C75B, 0x81B93F6E, 0x6026F07D,
	0x390EBA9C, 0xD891758F, 0x52998DBA, 0xB30642A9,
	0xEF89D4D0, 0x0E161BC3, 0x841EE3F6, 0x65812CE5,
	0x364E779D, 0xD7D1B88E, 0x5DD940BB, 0xBC468FA8,
	0xE0C919D1, 0x0156D6C2, 0x8B5E2EF7, 0x6AC1E1E4,
	0x33E9AB05, 0xD2766416, 0x587E9C23, 0xB9E15330,
	0xE56EC549, 0x04F10A5A, 0x8EF9F26F, 0x6F663D7C,
	0x50358897, 0xB1AA4784, 0x3BA2BFB1, 0xDA3D70A2,
	0x86B2E6DB, 0x672D29C8, 0xED25D1FD, 0x0CBA1EEE,
	0x5592540F, 0xB40D9B1C, 0x3E056329, 0xDF9AAC3A,
	0x83153A43, 0x628AF550, 0xE8820D65, 0x091DC276,
	0x5AD2990E, 0xBB4D561D, 0x3145AE28, 0xD0DA613B,
	0x8C55F742, 0x6DCA3851, 0xE7C2C064, 0x065D0F77,
	0x5F754596, 0xBEEA8A85, 0x34E272B0, 0xD57DBDA3,
	0x89F22BDA, 0x686DE4C9, 0xE2651CFC, 0x03FAD3EF,
	0x4452AA0C, 0xA5CD651F, 0x2FC59D2A, 0xCE5A5239,
	0x92D5C440, 0x734A0B53, 0xF942F366, 0x18DD3C75,
	0x41F57694, 0xA06AB987, 0x2A6241B2, 0xCBFD8EA1,
	0x977218D8, 0x76EDD7CB, 0xFCE52FFE, 0x1D7AE0ED,
	0x4EB5BB95, 0xAF2A7486, 0x25228CB3, 0xC4BD43A0,
	0x9832D5D9, 0x79AD1ACA, 0xF3A5E2FF, 0x123A2DEC,
	0x4B12670D, 0xAA8DA81E, 0x2085502B, 0xC11A9F38,
	0x9D950941, 0x7C0AC652, 0xF6023E67, 0x179DF174,
	0x78FBCC08, 0x9964031B, 0x136CFB2E, 0xF2F3343D,
	0xAE7CA244, 0x4FE36D57, 0xC5EB9562, 0x24745A71,
	0x7D5C1090, 0x9CC3DF83, 0x16CB27B6, 0xF754E8A5,
	0xABDB7EDC, 0x4A44B1CF, 0xC04C49FA, 0x21D386E9,
	0x721CDD91, 0x93831282, 0x198BEAB7, 0xF81425A4,
	0xA49BB3DD, 0x45047CCE, 0xCF0C84FB, 0x2E934BE8,
	0x77BB0109, 0x9624CE1A, 0x1C2C362F, 0xFDB3F93C,
	0xA13C6F45, 0x40A3A056, 0xCAAB5863, 0x2B349770,
	0x6C9CEE93, 0x8D032180, 0x070BD9B5, 0xE69416A6,
	0xBA1B80DF, 0x5B844FCC, 0xD18CB7F9, 0x301378EA,
	0x693B320B, 0x88A4FD18, 0x02AC052D, 0xE333CA3E,
	0xBFBC5C47, 0x5E239354, 0xD42B6B61, 0x35B4A472,
	0x667BFF0A, 0x87E43019, 0x0DECC82C, 0xEC73073F,
	0xB0FC9146, 0x51635E55, 0xDB6BA660, 0x3AF46973,
	0x63DC2392, 0x8243EC81, 0x084B14B4, 0xE9D4DBA7,
	0xB55B4DDE, 0x54C482CD, 0xDECC7AF8, 0x3F53B5EB
};

// Multiplication by 1/alpha: 1/alpha * x = (x >> 8) ^ mul_ia[x & 0xFF]
uint32_t mul_ia[] = {
	0x00000000, 0x180F40CD, 0x301E8033, 0x2811C0FE,
	0x603CA966, 0x7833E9AB, 0x50222955, 0x482D6998,
	0xC078FBCC, 0xD877BB01, 0xF0667BFF, 0xE8693B32,
	0xA04452AA, 0xB84B1267, 0x905AD299, 0x88559254,
	0x29F05F31, 0x31FF1FFC, 0x19EEDF02, 0x01E19FCF,
	0x49CCF657, 0x51C3B69A, 0x79D27664, 0x61DD36A9,
	0xE988A4FD, 0xF187E430, 0xD99624CE, 0xC1996403,
	0x89B40D9B, 0x91BB4D56, 0xB9AA8DA8, 0xA1A5CD65,
	0x5249BE62, 0x4A46FEAF, 0x62573E51, 0x7A587E9C,
	0x32751704, 0x2A7A57C9, 0x026B9737, 0x1A64D7FA,
	0x923145AE, 0x8A3E0563, 0xA22FC59D, 0xBA208550,
	0xF20DECC8, 0xEA02AC05, 0xC2136CFB, 0xDA1C2C36,
	0x7BB9E153, 0x63B6A19E, 0x4BA76160, 0x53A821AD,
	0x1B854835, 0x038A08F8, 0x2B9BC806, 0x339488CB,
	0xBBC11A9F, 0xA3CE5A52, 0x8BDF9AAC, 0x93D0DA61,
	0xDBFDB3F9, 0xC3F2F334, 0xEBE333CA, 0xF3EC7307,
	0xA492D5C4, 0xBC9D9509, 0x948C55F7, 0x8C83153A,
	0xC4AE7CA2, 0xDCA13C6F, 0xF4B0FC91, 0xECBFBC5C,
	0x64EA2E08, 0x7CE56EC5, 0x54F4AE3B, 0x4CFBEEF6,
	0x04D6876E, 0x1CD9C7A3, 0x34C8075D, 0x2CC74790,
	0x8D628AF5, 0x956DCA38, 0xBD7C0AC6, 0xA5734A0B,
	0xED5E2393, 0xF551635E, 0xDD40A3A0, 0xC54FE36D,
	0x4D1A7139, 0x551531F4, 0x7D04F10A, 0x650BB1C7,
	0x2D26D85F, 0x35299892, 0x1D38586C, 0x053718A1,
	0xF6DB6BA6, 0xEED42B6B, 0xC6C5EB95, 0xDECAAB58,
	0x96E7C2C0, 0x8EE8820D, 0xA6F942F3, 0xBEF6023E,
	0x36A3906A, 0x2EACD0A7, 0x06BD1059, 0x1EB25094,
	0x569F390C, 0x4E9079C1, 0x6681B93F, 0x7E8EF9F2,
	0xDF2B3497, 0xC724745A, 0xEF35B4A4, 0xF73AF469,
	0xBF179DF1, 0xA718DD3C, 0x8F091DC2, 0x97065D0F,
	0x1F53CF5B, 0x075C8F96, 0x2F4D4F68, 0x37420FA5,
	0x7F6F663D, 0x676026F0, 0x4F71E60E, 0x577EA6C3,
	0xE18D0321, 0xF98243EC, 0xD1938312, 0xC99CC3DF,
	0x81B1AA47, 0x99BEEA8A, 0xB1AF2A74, 0xA9A06AB9,
	0x21F5F8ED, 0x39FAB820, 0x11EB78DE, 0x09E43813,
	0x41C9518B, 0x59C61146, 0x71D7D1B8, 0x69D89175,
	0xC87D5C10, 0xD0721CDD, 0xF863DC23, 0xE06C9CEE,
	0xA841F576, 0xB04EB5BB, 0x985F7545, 0x80503588,
	0x0805A7DC, 0x100AE711, 0x381B27EF, 0x20146722,
	0x68390EBA, 0x70364E77, 0x58278E89, 0x4028CE44,
	0xB3C4BD43, 0xABCBFD8E, 0x83DA3D70, 0x9BD57DBD,
	0xD3F81425, 0xCBF754E8, 0xE3E69416, 0xFBE9D4DB,
	0x73BC468F, 0x6BB30642, 0x43A2C6BC, 0x5BAD8671,
	0x1380EFE9, 0x0B8FAF24, 0x239E6FDA, 0x3B912F17,
	0x9A34E272, 0x823BA2BF, 0xAA2A6241, 0xB225228C,
	0xFA084B14, 0xE2070BD9, 0xCA16CB27, 0xD2198BEA,
	0x5A4C19BE, 0x42435973, 0x6A52998D, 0x725DD940,
	0x3A70B0D8, 0x227FF015, 0x0A6E30EB, 0x12617026,
	0x451FD6E5, 0x5D109628, 0x750156D6, 0x6D0E161B,
	0x25237F83, 0x3D2C3F4E, 0x153DFFB0, 0x0D32BF7D,
	0x85672D29, 0x9D686DE4, 0xB579AD1A, 0xAD76EDD7,
	0xE55B844F, 0xFD54C482, 0xD545047C, 0xCD4A44B1,
	0x6CEF89D4, 0x74E0C919, 0x5CF109E7, 0x44FE492A,
	0x0CD320B2, 0x14DC607F, 0x3CCDA081, 0x24C2E04C,
	0xAC977218, 0xB49832D5, 0x9C89F22B, 0x8486B2E6,
	0xCCABDB7E, 0xD4A49BB3, 0xFCB55B4D, 0xE4BA1B80,
	0x17566887, 0x0F59284A, 0x2748E8B4, 0x3F47A879,
	0x776AC1E1, 0x6F65812C, 0x477441D2, 0x5F7B011F,
	0xD72E934B, 0xCF21D386, 0xE7301378, 0xFF3F53B5,
	0xB7123A2D, 0xAF1D7AE0, 0x870CBA1E, 0x9F03FAD3,
	0x3EA637B6, 0x26A9777B, 0x0EB8B785, 0x16B7F748,
	0x5E9A9ED0, 0x4695DE1D, 0x6E841EE3, 0x768B5E2E,
	0xFEDECC7A, 0xE6D18CB7, 0xCEC04C49, 0xD6CF0C84,
	0x9EE2651C, 0x86ED25D1, 0xAEFCE52F, 0xB6F3A5E2
};

/*
 * Sosemanuk context
 * keylen - chipher key length in bytes
 * ivlen - vector initialization length in bytes
 * key - chiper key
 * iv - initialization vector
 * sk - array subkey for Serpent24
 * s - array internal cipher state
 * r1 - internal cipher state
 * r2 - internal cipher state
*/
struct sosemanuk_context {
	int keylen;
	int ivlen;
	uint8_t key[32];
	uint8_t iv[16];
	uint32_t sk[100];
	uint32_t s[10];
	uint32_t r1;
	uint32_t r2;
};

// Allocates memory for the sosemanuk_context
struct sosemanuk_context *
sosemanuk_context_new(void)
{
	struct sosemanuk_context *ctx;
	ctx = (struct sosemanuk_context *)malloc(sizeof(*ctx));

	if(ctx == NULL)
		return NULL;
	
	memset(ctx, 0, sizeof(*ctx));

	return ctx;
}

// Delete sosemanuk_context
void
sosemanuk_context_free(struct sosemanuk_context **ctx)
{
	free(*ctx);
	*ctx = NULL;
}

// IV injection: using a block cipher Serpent24. Output is used 12th, 18th and 24th rounds Serpent24
// Subkeys write in array s (ctx->s) and registers r1, r2
static void
sosemanuk_ivsetup(struct sosemanuk_context *ctx)
{
	uint32_t r0, r1, r2, r3, r4;

	r0 = U8TO32_LITTLE(ctx->iv);
	r1 = U8TO32_LITTLE(ctx->iv + 4);
	r2 = U8TO32_LITTLE(ctx->iv + 8);
	r3 = U8TO32_LITTLE(ctx->iv + 12);

	FSS( 0, S0, 0, 1, 2, 3, 4, 1, 4, 2, 0);
	FSS( 4, S1, 1, 4, 2, 0, 3, 2, 1, 0, 4);
	FSS( 8, S2, 2, 1, 0, 4, 3, 0, 4, 1, 3);
	FSS(12, S3, 0, 4, 1, 3, 2, 4, 1, 3, 2);
	FSS(16, S4, 4, 1, 3, 2, 0, 1, 0, 4, 2);
	FSS(20, S5, 1, 0, 4, 2, 3, 0, 2, 1, 4);
	FSS(24, S6, 0, 2, 1, 4, 3, 0, 2, 3, 1);
	FSS(28, S7, 0, 2, 3, 1, 4, 4, 1, 2, 0);
	FSS(32, S0, 4, 1, 2, 0, 3, 1, 3, 2, 4);
	FSS(36, S1, 1, 3, 2, 4, 0, 2, 1, 4, 3);
	FSS(40, S2, 2, 1, 4, 3, 0, 4, 3, 1, 0);
	FSS(44, S3, 4, 3, 1, 0, 2, 3, 1, 0, 2);
	
	ctx->s[9] = r3;
	ctx->s[8] = r1;
	ctx->s[7] = r0;
	ctx->s[6] = r2;

	FSS(48, S4, 3, 1, 0, 2, 4, 1, 4, 3, 2);
	FSS(52, S5, 1, 4, 3, 2, 0, 4, 2, 1, 3);
	FSS(56, S6, 4, 2, 1, 3, 0, 4, 2, 0, 1);
	FSS(60, S7, 4, 2, 0, 1, 3, 3, 1, 2, 4);
	FSS(64, S0, 3, 1, 2, 4, 0, 1, 0, 2, 3);
	FSS(68, S1, 1, 0, 2, 3, 4, 2, 1, 3, 0);

	ctx->r1 = r2;
	ctx->s[4] = r1;
	ctx->r2 = r3;
	ctx->s[5] = r0;

	FSS(72, S2, 2, 1, 3, 0, 4, 3, 0, 1, 4);
	FSS(76, S3, 3, 0, 1, 4, 2, 0, 1, 4, 2);
	FSS(80, S4, 0, 1, 4, 2, 3, 1, 3, 0, 2);
	FSS(84, S5, 1, 3, 0, 2, 4, 3, 2, 1, 0);
	FSS(88, S6, 3, 2, 1, 0, 4, 3, 2, 4, 1);
	FSF(92, S7, 3, 2, 4, 1, 0, 0, 1, 2, 3);

	ctx->s[3] = r0;
	ctx->s[2] = r1;
	ctx->s[1] = r2;
	ctx->s[0] = r3;
}

// Key schedule: produces 25 128-bit subkeys as 100 32-bit words (write in array sk[100]) 
static void
sosemanuk_keysetup(struct sosemanuk_context *ctx)
{
	uint32_t w0, w1, w2, w3, w4, w5, w6, w7;
	int i = 0;

	w0 = U8TO32_LITTLE(ctx->key + 0);
	w1 = U8TO32_LITTLE(ctx->key + 4);
	w2 = U8TO32_LITTLE(ctx->key + 8);
	w3 = U8TO32_LITTLE(ctx->key + 12);
	w4 = U8TO32_LITTLE(ctx->key + 16);
	w5 = U8TO32_LITTLE(ctx->key + 20);
	w6 = U8TO32_LITTLE(ctx->key + 24);
	w7 = U8TO32_LITTLE(ctx->key + 28);

	WUP0(0);  SKS3; 
	WUP1(4);  SKS2; 
	WUP0(8);  SKS1; 
	WUP1(12); SKS0; 
	WUP0(16); SKS7; 
	WUP1(20); SKS6; 
	WUP0(24); SKS5; 
	WUP1(28); SKS4; 
	WUP0(32); SKS3; 
	WUP1(36); SKS2; 
	WUP0(40); SKS1; 
	WUP1(44); SKS0; 
	WUP0(48); SKS7; 
	WUP1(52); SKS6; 
	WUP0(56); SKS5; 
	WUP1(60); SKS4; 
	WUP0(64); SKS3; 
	WUP1(68); SKS2; 
	WUP0(72); SKS1; 
	WUP1(76); SKS0; 
	WUP0(80); SKS7; 
	WUP1(84); SKS6; 
	WUP0(88); SKS5; 
	WUP1(92); SKS4; 
	WUP0(96); SKS3;

	sosemanuk_ivsetup(ctx);
}

// Fill the sosemanuk_context (key and iv)
// Return value: 0 (if all is well), -1 (is all bad)
int
sosemanuk_set_key_and_iv(struct sosemanuk_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[16], const int ivlen)
{
	if((keylen > 0) && (keylen <= SOSEMANUK))
		ctx->keylen = keylen;
	else
		return -1;
	
	if((ivlen > 0) && (ivlen <= 16))
		ctx->ivlen = ivlen;
	else
		return -1;
	
	memcpy(ctx->key, key, ctx->keylen);
	memcpy(ctx->iv, iv, ctx->ivlen);
	
	sosemanuk_keysetup(ctx);

	return 0;
}

// Function generate keystream
static void
sosemanuk_generate_keystream(struct sosemanuk_context *ctx, uint32_t *keystream)
{
	uint32_t r1, r2, u0, u1, u2, u3, u4, v0, v1, v2, v3;
	uint32_t s0, s1, s2, s3, s4, s5, s6, s7, s8, s9;

	s0 = ctx->s[0];
	s1 = ctx->s[1];
	s2 = ctx->s[2];
	s3 = ctx->s[3];
	s4 = ctx->s[4];
	s5 = ctx->s[5];
	s6 = ctx->s[6];
	s7 = ctx->s[7];
	s8 = ctx->s[8];
	s9 = ctx->s[9];
	r1 = ctx->r1;
	r2 = ctx->r2;

	STEP(0, 1, 3, 8, 9, v0, u0);
	STEP(1, 2, 4, 9, 0, v1, u1);
	STEP(2, 3, 5, 0, 1, v2, u2);
	STEP(3, 4, 6, 1, 2, v3, u3);

	SRD(S2, 2, 3, 1, 4, 0);

	STEP(4, 5, 7, 2, 3, v0, u0);
	STEP(5, 6, 8, 3, 4, v1, u1);
	STEP(6, 7, 9, 4, 5, v2, u2);
	STEP(7, 8, 0, 5, 6, v3, u3);

	SRD(S2, 2, 3, 1, 4, 4);

	STEP(8, 9, 1, 6, 7, v0, u0);
	STEP(9, 0, 2, 7, 8, v1, u1);
	STEP(0, 1, 3, 8, 9, v2, u2);
	STEP(1, 2, 4, 9, 0, v3, u3);

	SRD(S2, 2, 3, 1, 4, 8);

	STEP(2, 3, 5, 0, 1, v0, u0);
	STEP(3, 4, 6, 1, 2, v1, u1);
	STEP(4, 5, 7, 2, 3, v2, u2);
	STEP(5, 6, 8, 3, 4, v3, u3);
	
	SRD(S2, 2, 3, 1, 4, 12);

	STEP(6, 7, 9, 4, 5, v0, u0);
	STEP(7, 8, 0, 5, 6, v1, u1);
	STEP(8, 9, 1, 6, 7, v2, u2);
	STEP(9, 0, 2, 7, 8, v3, u3);

	SRD(S2, 2, 3, 1, 4, 16);

	ctx->s[0] = s0;
	ctx->s[1] = s1;
	ctx->s[2] = s2;
	ctx->s[3] = s3;
	ctx->s[4] = s4;
	ctx->s[5] = s5;
	ctx->s[6] = s6;
	ctx->s[7] = s7;
	ctx->s[8] = s8;
	ctx->s[9] = s9;
	ctx->r1 = r1;
	ctx->r2 = r2;
}

/*
 * Sosemanuk encrypt function
 * ctx - pointer on sosemanuk_context
 * buf - pointer on buffer data
 * buflen - length the data buffer
 * out - pointer on output
*/
void
sosemanuk_encrypt(struct sosemanuk_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	uint32_t keystream[20];
	uint32_t i;

	for(; buflen >= 80; buflen -= 80, buf += 80, out += 80) {
		sosemanuk_generate_keystream(ctx, keystream);
		
		*(uint32_t *)(out +  0) = *(uint32_t *)(buf +  0) ^ keystream[ 0];
		*(uint32_t *)(out +  4) = *(uint32_t *)(buf +  4) ^ keystream[ 1];
		*(uint32_t *)(out +  8) = *(uint32_t *)(buf +  8) ^ keystream[ 2];
		*(uint32_t *)(out + 12) = *(uint32_t *)(buf + 12) ^ keystream[ 3];
		*(uint32_t *)(out + 16) = *(uint32_t *)(buf + 16) ^ keystream[ 4];
		*(uint32_t *)(out + 20) = *(uint32_t *)(buf + 20) ^ keystream[ 5];
		*(uint32_t *)(out + 24) = *(uint32_t *)(buf + 24) ^ keystream[ 6];
		*(uint32_t *)(out + 28) = *(uint32_t *)(buf + 28) ^ keystream[ 7];
		*(uint32_t *)(out + 32) = *(uint32_t *)(buf + 32) ^ keystream[ 8];
		*(uint32_t *)(out + 36) = *(uint32_t *)(buf + 36) ^ keystream[ 9];
		*(uint32_t *)(out + 40) = *(uint32_t *)(buf + 40) ^ keystream[10];
		*(uint32_t *)(out + 44) = *(uint32_t *)(buf + 44) ^ keystream[11];
		*(uint32_t *)(out + 48) = *(uint32_t *)(buf + 48) ^ keystream[12];
		*(uint32_t *)(out + 52) = *(uint32_t *)(buf + 52) ^ keystream[13];
		*(uint32_t *)(out + 56) = *(uint32_t *)(buf + 56) ^ keystream[14];
		*(uint32_t *)(out + 60) = *(uint32_t *)(buf + 60) ^ keystream[15];
		*(uint32_t *)(out + 64) = *(uint32_t *)(buf + 64) ^ keystream[16];
		*(uint32_t *)(out + 68) = *(uint32_t *)(buf + 68) ^ keystream[17];
		*(uint32_t *)(out + 72) = *(uint32_t *)(buf + 72) ^ keystream[18];
		*(uint32_t *)(out + 76) = *(uint32_t *)(buf + 76) ^ keystream[19];
	}

	if(buflen > 0) {
		sosemanuk_generate_keystream(ctx, keystream);	
	
		for(i = 0; i < buflen; i++)
			out[i] = buf[i] ^ ((uint8_t *)keystream)[i];
	}
}

// Soemanuk decrypt function. See sosemanuk_encrypt
void
sosemanuk_decrypt(struct sosemanuk_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	sosemanuk_encrypt(ctx, buf, buflen, out);
}

void
sosemanuk_test_vectors(struct sosemanuk_context *ctx)
{
	uint32_t keystream[20];
	int i;

	sosemanuk_generate_keystream(ctx, keystream);

	printf("\n Test vectors for the Sosemanuk:\n");
	
	printf("\nKey:       ");

	for(i = 0; i < 32; i++)
		printf("%02x ", ctx->key[i]);
	
	printf("\nIV:        ");

	for(i = 0; i < 16; i++)
		printf("%02x ", ctx->iv[i]);
	
	printf("\nKeystream: ");
	
	for(i = 0; i < 20; i++)
		PRINT_U32TO32(keystream[i]);
		
	printf("\n\n");
}
//----------------------------------------------



// The stream algorithm TRIVIUM
//----------------------------------------------

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

/* 
 * Trivium context 
 * keylen - chiper key length in bytes
 * ivlen - vector initialization length in bytes
 * key - chiper key
 * iv - initialization vector
 * w - array of intermediate calculations
*/
struct trivium_context {
	int keylen;
	int ivlen;
	uint8_t key[10];
	uint8_t iv[10];
	uint32_t w[10];
};

// Allocates memory for the trivium context
struct trivium_context *
trivium_context_new(void)
{
	struct trivium_context *ctx;
	ctx = (struct trivium_context *)malloc(sizeof(*ctx));

	if(ctx == NULL)
		return NULL;
	
	memset(ctx, 0, sizeof(*ctx));

	return ctx;
}

// Delete trivium context
void
trivium_context_free(struct trivium_context **ctx)
{
	free(*ctx);
	*ctx = NULL;
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
 * Trivium encrypt algorithm.
 * ctx - pointer on trivium context
 * buf - pointer on buffer data
 * buflen - length the data buffer
 * out - pointer on output array
*/
void
trivium_encrypt(struct trivium_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
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

// Trivium decrypt function. See trivium_encrypt
void
trivium_decrypt(struct trivium_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	trivium_encrypt(ctx, buf, buflen, out);
}

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

//----------------------------------------------

