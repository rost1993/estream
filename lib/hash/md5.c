/*
 * This program implements the MD5 hash functions RFC 1321.
 * Author MD5 algorithm - Ronald Linn Rivest, Massachusetts Institute of Technology.
 * 
 * Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * 27.08.2015, <rostislav-gashin@yandex.ru>
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "md5.h"
#include "../macro.h"

// Functions for the 4 rounds
#define F(x, y, z)	((x & y) | ((~x) & z))
#define G(x, y, z)	((x & z) | ((~z) & y))
#define H(x, y, z)	(x ^ y ^ z)
#define I(x, y, z)	(y ^ ((~z) | x))

/*
 * STEP - main step MD5 conversion
 * a, b, c, d - state 32-bit words
 * x - part of input block
 * n - amount of bits to rotate left
 * T - MD5 constant
 * F - MD5 functions
*/
#define STEP(a, b, c, d, x, n, T, F) {	\
	a+= F(b, c, d) + x + T;		\
	a = ROTL32(a, n);		\
	a += b;				\
}

// Single bit (byte 0x80), other 63 bytes are zero
static const unsigned char md5pad[64] = { 0x80 };

// Initialization function
void
md5_init(struct md5_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->state[0] = 0x67452301UL;
	ctx->state[1] = 0xEFCDAB89UL;
	ctx->state[2] = 0x98BADCFEUL;
	ctx->state[3] = 0x10325476UL;
}

// 32-byte array is transformed into 8-byte array
static void
uint32_to_bytes(uint8_t *out, const uint32_t *in, const int n)
{
	int x, y;

	for(x = y = 0; y < n; y++) {
		out[x++] = in[y] & 0xFF;
		out[x++] = (in[y] >> 8) & 0xFF;
		out[x++] = (in[y] >> 16) & 0xFF;
		out[x++] = (in[y] >> 24) & 0xFF;
	}
}

// MD5 algorithm
static void
md5_hash(uint32_t state[4], const uint8_t block[64])
{
	int i, j;
	uint32_t x[16];
	uint32_t a, b, c, d;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	for(i = j = 0; i < 16; i++, j += 4)
		x[i] = U8TO32_LITTLE(block + j);
	
	// First step
	STEP(a, b, c, d, x[ 0],  7, 0xD76AA478UL, F);
	STEP(d, a, b, c, x[ 1], 12, 0xE8C7B756UL, F);
	STEP(c, d, a, b, x[ 2], 17, 0x242070DBUL, F);
	STEP(b, c, d, a, x[ 3], 22, 0xC1BDCEEEUL, F);
	STEP(a, b, c, d, x[ 4],  7, 0xF57C0FAFUL, F);
	STEP(d, a, b, c, x[ 5], 12, 0x4787C62AUL, F);
	STEP(c, d, a, b, x[ 6], 17, 0xA8304613UL, F);
	STEP(b, c, d, a, x[ 7], 22, 0xFD469501UL, F);
	STEP(a, b, c, d, x[ 8],  7, 0x698098D8UL, F);
	STEP(d, a, b, c, x[ 9], 12, 0x8B44F7AFUL, F);
	STEP(c, d, a, b, x[10], 17, 0xFFFF5BB1UL, F);
	STEP(b, c, d, a, x[11], 22, 0x895CD7BEUL, F);
	STEP(a, b, c, d, x[12],  7, 0x6B901122UL, F);
	STEP(d, a, b, c, x[13], 12, 0xFD987193UL, F);
	STEP(c, d, a, b, x[14], 17, 0xA679438EUL, F);
	STEP(b, c, d, a, x[15], 22, 0x49B40821UL, F);

	// Second step
	STEP(a, b, c, d, x[ 1],  5, 0xF61E2562UL, G);
	STEP(d, a, b, c, x[ 6],  9, 0xC040B340UL, G);
	STEP(c, d, a, b, x[11], 14, 0x265E5A51UL, G);
	STEP(b, c, d, a, x[ 0], 20, 0xE9B6C7AAUL, G);
	STEP(a, b, c, d, x[ 5],  5, 0xD62F105DUL, G);
	STEP(d, a, b, c, x[10],  9, 0x02441453UL, G);
	STEP(c, d, a, b, x[15], 14, 0xD8A1E681UL, G);
	STEP(b, c, d, a, x[ 4], 20, 0xE7D3FBC8UL, G);
	STEP(a, b, c, d, x[ 9],  5, 0x21E1CDE6UL, G);
	STEP(d, a, b, c, x[14],  9, 0xC33707D6UL, G);
	STEP(c, d, a, b, x[ 3], 14, 0xF4D50D87UL, G);
	STEP(b, c, d, a, x[ 8], 20, 0x455A14EDUL, G);
	STEP(a, b, c, d, x[13],  5, 0xA9E3E905UL, G);
	STEP(d, a, b, c, x[ 2],  9, 0xFCEFA3F8UL, G);
	STEP(c, d, a, b, x[ 7], 14, 0x676F02D9UL, G);
	STEP(b, c, d, a, x[12], 20, 0x8D2A4C8AUL, G);

	// Third step
	STEP(a, b, c, d, x[ 5],  4, 0xFFFA3942UL, H);
	STEP(d, a, b, c, x[ 8], 11, 0x8771F681UL, H);
	STEP(c, d, a, b, x[11], 16, 0x6D9D6122UL, H);
	STEP(b, c, d, a, x[14], 23, 0xFDE5380CUL, H);
	STEP(a, b, c, d, x[ 1],  4, 0xA4BEEA44UL, H);
	STEP(d, a, b, c, x[ 4], 11, 0x4BDECFA9UL, H);
	STEP(c, d, a, b, x[ 7], 16, 0xF6BB4B60UL, H);
	STEP(b, c, d, a, x[10], 23, 0xBEBFBC70UL, H);
	STEP(a, b, c, d, x[13],  4, 0x289B7EC6UL, H);
	STEP(d, a, b, c, x[ 0], 11, 0xEAA127FAUL, H);
	STEP(c, d, a, b, x[ 3], 16, 0xD4EF3085UL, H);
	STEP(b, c, d, a, x[ 6], 23, 0x04881D05UL, H);
	STEP(a, b, c, d, x[ 9],  4, 0xD9D4D039UL, H);
	STEP(d, a, b, c, x[12], 11, 0xE6DB99E5UL, H);
	STEP(c, d, a, b, x[15], 16, 0x1FA27CF8UL, H);
	STEP(b, c, d, a, x[ 2], 23, 0xC4AC5665UL, H);

	// Fourth step
	STEP(a, b, c, d, x[ 0],  6, 0xF4292244UL, I);
	STEP(d, a, b, c, x[ 7], 10, 0x432AFF97UL, I);
	STEP(c, d, a, b, x[14], 15, 0xAB9423A7UL, I);
	STEP(b, c, d, a, x[ 5], 21, 0xFC93A039UL, I);
	STEP(a, b, c, d, x[12],  6, 0x655B59C3UL, I);
	STEP(d, a, b, c, x[ 3], 10, 0x8F0CCC92UL, I);
	STEP(c, d, a, b, x[10], 15, 0xFFEFF47DUL, I);
	STEP(b, c, d, a, x[ 1], 21, 0x85845DD1UL, I);
	STEP(a, b, c, d, x[ 8],  6, 0x6FA87E4FUL, I);
	STEP(d, a, b, c, x[15], 10, 0xFE2CE6E0UL, I);
	STEP(c, d, a, b, x[ 6], 15, 0xA3014314UL, I);
	STEP(b, c, d, a, x[13], 21, 0x4E0811A1UL, I);
	STEP(a, b, c, d, x[ 4],  6, 0xF7537E82UL, I);
	STEP(d, a, b, c, x[11], 10, 0xBD3AF235UL, I);
	STEP(c, d, a, b, x[ 2], 15, 0x2AD7D2BBUL, I);
	STEP(b, c, d, a, x[ 9], 21, 0xEB86D391UL, I);

	// MD5 hash save
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

// MD5 update function
// Caused by the addition of new data from calculate the hash
void
md5_update(struct md5_context *ctx, const void *message, uint32_t msglen)
{
	int n, len;

	n = (ctx->nbits[0] >> 3) & 0x3F;

	len = 64 - n;

	// Update bits length (msglen << 3 = msglen * 8)
	ctx->nbits[0] += msglen << 3;

	// Detect and fix overflow
	if(ctx->nbits[0] < (msglen << 3))
		++ctx->nbits[1];
	ctx->nbits[1] += msglen >> 29;

	if(msglen >= len) {
		
		// Calculate hash
		memcpy(ctx->buffer + n, message, len);
		message += len;
		msglen -= len;

		md5_hash(ctx->state, ctx->buffer);

		// Calculate hash of the remaining messages
		while(msglen >= 64) {
			md5_hash(ctx->state, message);
			message += 64;
			msglen -= 64;
		}

		n = 0;
	}

	// Save message remaining bytes of the buffer
	memcpy(ctx->buffer + n, message, msglen);
}

// Get the MD5 hash of the message
// MD5 hash located in array digest
void
md5_final(struct md5_context *ctx, uint8_t digest[16])
{
	uint8_t nbits[8];
	int n, npad;

	n = (ctx->nbits[0] >> 3) & 0x3F;
	npad = ((n < 56) ? 56 : 120) - n;

	uint32_to_bytes(nbits, ctx->nbits, 2);

	md5_update(ctx, md5pad, npad);
	md5_update(ctx, nbits, 8);

	uint32_to_bytes(digest, ctx->state, 4);
}

