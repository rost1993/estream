/*
 * This program implements the SHA1 hash functions RFC 3174.
 * Author SHA1 algorithm - NSA and NIST.
 * 
 * Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * 30.08.2015, <rostislav-gashin@yandex.ru>
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha1.h"
#include "../macro.h"

// SHA1 constant
#define K0	0x5A827999
#define K1	0x6ED9EBA1
#define K2	0x8F1BBCDC
#define K3	0xCA62C1D6

// Functions for the 80 rounds
#define F0(m, l, k)	((m & l) | ((~m) & k))
#define F1(m, l, k)	(m ^ l ^ k)
#define F2(m, l, k)	((m & l) | (m & k) | (l & k))

/*
 * STEP - main step SHA1 conversion
 * a, b, c, d, e - state 32-bit words
 * W - 32-bit word
 * K - SHA1 constant
 * F - SHA1 functions
*/
#define STEP(a, b, c, d, e, W, K, F) {			\
	uint32_t temp;					\
	temp = ROTL32(a, 5) + F(b, c, d) + e + W + K;	\
	e = d;						\
	d = c;						\
	c = ROTL32(b, 30);				\
	b = a;						\
	a = temp;					\
}

// Single bit (byte 0x80), other 63 bytes are zero
static uint8_t sha1pad[64] = { 0x80 };

// Initialization function
void
sha1_init(struct sha1_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
}

// 32-byte array is transformed into 8-byte array
static void
uint32_to_bytes(uint8_t *out, uint32_t *in, const int n)
{
	int x, y;

	for(x = y = 0; y < n; y++) {
		out[x++] = (in[y] >> 24) & 0xFF;
		out[x++] = (in[y] >> 16) & 0xFF;
		out[x++] = (in[y] >> 8) & 0xFF;
		out[x++] = in[y] & 0xFF;
	}
}

// SHA1 hash function
static void
sha1_hash(struct sha1_context *ctx, const uint8_t buffer[64])
{
	uint32_t W[80];
	uint32_t a, b, c, d, e;

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	W[ 0] = U8TO32_BIG(buffer);
	W[ 1] = U8TO32_BIG(buffer + 4);
	W[ 2] = U8TO32_BIG(buffer + 8);
	W[ 3] = U8TO32_BIG(buffer + 12);
	W[ 4] = U8TO32_BIG(buffer + 16);
	W[ 5] = U8TO32_BIG(buffer + 20);
	W[ 6] = U8TO32_BIG(buffer + 24);
	W[ 7] = U8TO32_BIG(buffer + 28);
	W[ 8] = U8TO32_BIG(buffer + 32);
	W[ 9] = U8TO32_BIG(buffer + 36);
	W[10] = U8TO32_BIG(buffer + 40);
	W[11] = U8TO32_BIG(buffer + 44);
	W[12] = U8TO32_BIG(buffer + 48);
	W[13] = U8TO32_BIG(buffer + 52);
	W[14] = U8TO32_BIG(buffer + 56);
	W[15] = U8TO32_BIG(buffer + 60);

	W[16] = ROTL32((W[13] ^ W[ 8] ^ W[ 2] ^ W[ 0]), 1);
	W[17] = ROTL32((W[14] ^ W[ 9] ^ W[ 3] ^ W[ 1]), 1);
	W[18] = ROTL32((W[15] ^ W[10] ^ W[ 4] ^ W[ 2]), 1);
	W[19] = ROTL32((W[16] ^ W[11] ^ W[ 5] ^ W[ 3]), 1);
	W[20] = ROTL32((W[17] ^ W[12] ^ W[ 6] ^ W[ 4]), 1);
	W[21] = ROTL32((W[18] ^ W[13] ^ W[ 7] ^ W[ 5]), 1);
	W[22] = ROTL32((W[19] ^ W[14] ^ W[ 8] ^ W[ 6]), 1);
	W[23] = ROTL32((W[20] ^ W[15] ^ W[ 9] ^ W[ 7]), 1);
	W[24] = ROTL32((W[21] ^ W[16] ^ W[10] ^ W[ 8]), 1);
	W[25] = ROTL32((W[22] ^ W[17] ^ W[11] ^ W[ 9]), 1);
	W[26] = ROTL32((W[23] ^ W[18] ^ W[12] ^ W[10]), 1);
	W[27] = ROTL32((W[24] ^ W[19] ^ W[13] ^ W[11]), 1);
	W[28] = ROTL32((W[25] ^ W[20] ^ W[14] ^ W[12]), 1);
	W[29] = ROTL32((W[26] ^ W[21] ^ W[15] ^ W[13]), 1);
	W[30] = ROTL32((W[27] ^ W[22] ^ W[16] ^ W[14]), 1);
	W[31] = ROTL32((W[28] ^ W[23] ^ W[17] ^ W[15]), 1);
	W[32] = ROTL32((W[29] ^ W[24] ^ W[18] ^ W[16]), 1);
	W[33] = ROTL32((W[30] ^ W[25] ^ W[19] ^ W[17]), 1);
	W[34] = ROTL32((W[31] ^ W[26] ^ W[20] ^ W[18]), 1);
	W[35] = ROTL32((W[32] ^ W[27] ^ W[21] ^ W[19]), 1);
	W[36] = ROTL32((W[33] ^ W[28] ^ W[22] ^ W[20]), 1);
	W[37] = ROTL32((W[34] ^ W[29] ^ W[23] ^ W[21]), 1);
	W[38] = ROTL32((W[35] ^ W[30] ^ W[24] ^ W[22]), 1);
	W[39] = ROTL32((W[36] ^ W[31] ^ W[25] ^ W[23]), 1);
	W[40] = ROTL32((W[37] ^ W[32] ^ W[26] ^ W[24]), 1);
	W[41] = ROTL32((W[38] ^ W[33] ^ W[27] ^ W[25]), 1);
	W[42] = ROTL32((W[39] ^ W[34] ^ W[28] ^ W[26]), 1);
	W[43] = ROTL32((W[40] ^ W[35] ^ W[29] ^ W[27]), 1);
	W[44] = ROTL32((W[41] ^ W[36] ^ W[30] ^ W[28]), 1);
	W[45] = ROTL32((W[42] ^ W[37] ^ W[31] ^ W[29]), 1);
	W[46] = ROTL32((W[43] ^ W[38] ^ W[32] ^ W[30]), 1);
	W[47] = ROTL32((W[44] ^ W[39] ^ W[33] ^ W[31]), 1);
	W[48] = ROTL32((W[45] ^ W[40] ^ W[34] ^ W[32]), 1);
	W[49] = ROTL32((W[46] ^ W[41] ^ W[35] ^ W[33]), 1);
	W[50] = ROTL32((W[47] ^ W[42] ^ W[36] ^ W[34]), 1);
	W[51] = ROTL32((W[48] ^ W[43] ^ W[37] ^ W[35]), 1);
	W[52] = ROTL32((W[49] ^ W[44] ^ W[38] ^ W[36]), 1);
	W[53] = ROTL32((W[50] ^ W[45] ^ W[39] ^ W[37]), 1);
	W[54] = ROTL32((W[51] ^ W[46] ^ W[40] ^ W[38]), 1);
	W[55] = ROTL32((W[52] ^ W[47] ^ W[41] ^ W[39]), 1);
	W[56] = ROTL32((W[53] ^ W[48] ^ W[42] ^ W[40]), 1);
	W[57] = ROTL32((W[54] ^ W[49] ^ W[43] ^ W[41]), 1);
	W[58] = ROTL32((W[55] ^ W[50] ^ W[44] ^ W[42]), 1);
	W[59] = ROTL32((W[56] ^ W[51] ^ W[45] ^ W[43]), 1);
	W[60] = ROTL32((W[57] ^ W[52] ^ W[46] ^ W[44]), 1);
	W[61] = ROTL32((W[58] ^ W[53] ^ W[47] ^ W[45]), 1);
	W[62] = ROTL32((W[59] ^ W[54] ^ W[48] ^ W[46]), 1);
	W[63] = ROTL32((W[60] ^ W[55] ^ W[49] ^ W[47]), 1);
	W[64] = ROTL32((W[61] ^ W[56] ^ W[50] ^ W[48]), 1);
	W[65] = ROTL32((W[62] ^ W[57] ^ W[51] ^ W[49]), 1);
	W[66] = ROTL32((W[63] ^ W[58] ^ W[52] ^ W[50]), 1);
	W[67] = ROTL32((W[64] ^ W[59] ^ W[53] ^ W[51]), 1);
	W[68] = ROTL32((W[65] ^ W[60] ^ W[54] ^ W[52]), 1);
	W[69] = ROTL32((W[66] ^ W[61] ^ W[55] ^ W[53]), 1);
	W[70] = ROTL32((W[67] ^ W[62] ^ W[56] ^ W[54]), 1);
	W[71] = ROTL32((W[68] ^ W[63] ^ W[57] ^ W[55]), 1);
	W[72] = ROTL32((W[69] ^ W[64] ^ W[58] ^ W[56]), 1);
	W[73] = ROTL32((W[70] ^ W[65] ^ W[59] ^ W[57]), 1);
	W[74] = ROTL32((W[71] ^ W[66] ^ W[60] ^ W[58]), 1);
	W[75] = ROTL32((W[72] ^ W[67] ^ W[61] ^ W[59]), 1);
	W[76] = ROTL32((W[73] ^ W[68] ^ W[62] ^ W[60]), 1);
	W[77] = ROTL32((W[74] ^ W[69] ^ W[63] ^ W[61]), 1);
	W[78] = ROTL32((W[75] ^ W[70] ^ W[64] ^ W[62]), 1);
	W[79] = ROTL32((W[76] ^ W[71] ^ W[65] ^ W[63]), 1);

	// First step
	STEP(a, b, c, d, e, W[ 0], K0, F0);
	STEP(a, b, c, d, e, W[ 1], K0, F0);
	STEP(a, b, c, d, e, W[ 2], K0, F0);
	STEP(a, b, c, d, e, W[ 3], K0, F0);
	STEP(a, b, c, d, e, W[ 4], K0, F0);
	STEP(a, b, c, d, e, W[ 5], K0, F0);
	STEP(a, b, c, d, e, W[ 6], K0, F0);
	STEP(a, b, c, d, e, W[ 7], K0, F0);
	STEP(a, b, c, d, e, W[ 8], K0, F0);
	STEP(a, b, c, d, e, W[ 9], K0, F0);
	STEP(a, b, c, d, e, W[10], K0, F0);
	STEP(a, b, c, d, e, W[11], K0, F0);
	STEP(a, b, c, d, e, W[12], K0, F0);
	STEP(a, b, c, d, e, W[13], K0, F0);
	STEP(a, b, c, d, e, W[14], K0, F0);
	STEP(a, b, c, d, e, W[15], K0, F0);
	STEP(a, b, c, d, e, W[16], K0, F0);
	STEP(a, b, c, d, e, W[17], K0, F0);
	STEP(a, b, c, d, e, W[18], K0, F0);
	STEP(a, b, c, d, e, W[19], K0, F0);

	// Second step
	STEP(a, b, c, d, e, W[20], K1, F1);
	STEP(a, b, c, d, e, W[21], K1, F1);
	STEP(a, b, c, d, e, W[22], K1, F1);
	STEP(a, b, c, d, e, W[23], K1, F1);
	STEP(a, b, c, d, e, W[24], K1, F1);
	STEP(a, b, c, d, e, W[25], K1, F1);
	STEP(a, b, c, d, e, W[26], K1, F1);
	STEP(a, b, c, d, e, W[27], K1, F1);
	STEP(a, b, c, d, e, W[28], K1, F1);
	STEP(a, b, c, d, e, W[29], K1, F1);
	STEP(a, b, c, d, e, W[30], K1, F1);
	STEP(a, b, c, d, e, W[31], K1, F1);
	STEP(a, b, c, d, e, W[32], K1, F1);
	STEP(a, b, c, d, e, W[33], K1, F1);
	STEP(a, b, c, d, e, W[34], K1, F1);
	STEP(a, b, c, d, e, W[35], K1, F1);
	STEP(a, b, c, d, e, W[36], K1, F1);
	STEP(a, b, c, d, e, W[37], K1, F1);
	STEP(a, b, c, d, e, W[38], K1, F1);
	STEP(a, b, c, d, e, W[39], K1, F1);

	// Third step
	STEP(a, b, c, d, e, W[40], K2, F2);
	STEP(a, b, c, d, e, W[41], K2, F2);
	STEP(a, b, c, d, e, W[42], K2, F2);
	STEP(a, b, c, d, e, W[43], K2, F2);
	STEP(a, b, c, d, e, W[44], K2, F2);
	STEP(a, b, c, d, e, W[45], K2, F2);
	STEP(a, b, c, d, e, W[46], K2, F2);
	STEP(a, b, c, d, e, W[47], K2, F2);
	STEP(a, b, c, d, e, W[48], K2, F2);
	STEP(a, b, c, d, e, W[49], K2, F2);
	STEP(a, b, c, d, e, W[50], K2, F2);
	STEP(a, b, c, d, e, W[51], K2, F2);
	STEP(a, b, c, d, e, W[52], K2, F2);
	STEP(a, b, c, d, e, W[53], K2, F2);
	STEP(a, b, c, d, e, W[54], K2, F2);
	STEP(a, b, c, d, e, W[55], K2, F2);
	STEP(a, b, c, d, e, W[56], K2, F2);
	STEP(a, b, c, d, e, W[57], K2, F2);
	STEP(a, b, c, d, e, W[58], K2, F2);
	STEP(a, b, c, d, e, W[59], K2, F2);

	// Fourth step
	STEP(a, b, c, d, e, W[60], K3, F1);
	STEP(a, b, c, d, e, W[61], K3, F1);
	STEP(a, b, c, d, e, W[62], K3, F1);
	STEP(a, b, c, d, e, W[63], K3, F1);
	STEP(a, b, c, d, e, W[64], K3, F1);
	STEP(a, b, c, d, e, W[65], K3, F1);
	STEP(a, b, c, d, e, W[66], K3, F1);
	STEP(a, b, c, d, e, W[67], K3, F1);
	STEP(a, b, c, d, e, W[68], K3, F1);
	STEP(a, b, c, d, e, W[69], K3, F1);
	STEP(a, b, c, d, e, W[70], K3, F1);
	STEP(a, b, c, d, e, W[71], K3, F1);
	STEP(a, b, c, d, e, W[72], K3, F1);
	STEP(a, b, c, d, e, W[73], K3, F1);
	STEP(a, b, c, d, e, W[74], K3, F1);
	STEP(a, b, c, d, e, W[75], K3, F1);
	STEP(a, b, c, d, e, W[76], K3, F1);
	STEP(a, b, c, d, e, W[77], K3, F1);
	STEP(a, b, c, d, e, W[78], K3, F1);
	STEP(a, b, c, d, e, W[79], K3, F1);

	// SHA1 hash save
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

// SHA1 update function
// Caused by the addition of new data from calculate the hash
void
sha1_update(struct sha1_context *ctx, const void *message, uint32_t msglen)
{
	int n, len;

	n = ctx->nbits[0] & 0x3F;

	len = 64 - n;

	// Update bits length
	ctx->nbits[0] += msglen;

	// Detect and fix overflow
	if(ctx->nbits[0] < msglen)
		++ctx->nbits[1];

	if(msglen >= len) {
		
		// Calculate hash
		memcpy(ctx->buffer + n, message, len);
		message += len;
		msglen -= len;

		sha1_hash(ctx, ctx->buffer);

		// Calculate hash of the remaining messages
		while(msglen >= 64) {
			sha1_hash(ctx, message);
			message += 64;
			msglen -= 64;
		}
	
		n = 0;
	}

	// Save message remaining bytes of the buffer
	if(msglen > 0)
		memcpy(ctx->buffer + n, message, msglen);
}

// Get the SHA1 hash of the message
// SHA1 hash located in array digest
void
sha1_final(struct sha1_context *ctx, uint8_t digest[20])
{
	uint32_t nbits[2];
	uint8_t nb[8];
	int n, npad;

	n = ctx->nbits[0] & 0x3F;
	npad = ((n < 56) ? 56 : 120) - n;

	nbits[0] = ctx->nbits[1] << 3;
	nbits[0] += ctx->nbits[0] >> 29;
	nbits[1] = ctx->nbits[0] << 3;

	memset(nb, 0, sizeof(nb));
	
	uint32_to_bytes(nb, nbits, 2);

	sha1_update(ctx, sha1pad, npad);
	sha1_update(ctx, nb, 8);

	uint32_to_bytes(digest, ctx->state, 5);
}

