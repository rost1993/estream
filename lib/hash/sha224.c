/*
 * This program implements the SHA224 hash functions RFC 4634.
 * Author SHA224 algorithm - NSA and NIST.
 *
 * Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * 01.09.2015, <rostislav-gashin@yandex.ru>
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha224.h"
#include "../macro.h"

// Functions for the SHA224 algorithm
#define CH(x, y, z)	((x & y) ^ ((~x) & z))
#define MAJ(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
#define SIGMA0(x)	(ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define SIGMA1(x)	(ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define DELTA0(x)	(ROTR32(x, 7) ^ ROTR32(x, 18) ^ SHR(x, 3))
#define DELTA1(x)	(ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHR(x, 10))

/*
 * STEP - main step SHA224 conversion
 * a, b, c, d, e, f, g, h - state 32-bit word
 * W - 32-bit word
 * K - SHA224 constant
*/
#define STEP(a, b, c, d, e, f, g, h, W, K) {		\
	uint32_t temp1, temp2;				\
	temp1 = h + SIGMA1(e) + CH(e, f, g) + W + K;	\
	temp2 = SIGMA0(a) + MAJ(a, b, c);		\
	h = g;						\
	g = f;						\
	f = e;						\
	e = d + temp1;					\
	d = c;						\
	c = b;						\
	b = a;						\
	a = temp1 + temp2;				\
}

// Single bit (byte 0x80), other 63 bytes are zero
const uint8_t sha224pad[64] = { 0x80 };

// SHA224 64 constant
static const uint32_t K[64] = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2 };

// Initialization function
void
sha224_init(struct sha224_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->state[0] = 0xC1059ED8;
	ctx->state[1] = 0x367CD507;
	ctx->state[2] = 0x3070DD17;
	ctx->state[3] = 0xF70E5939;
	ctx->state[4] = 0xFFC00B31;
	ctx->state[5] = 0x68581511;
	ctx->state[6] = 0x64F98FA7;
	ctx->state[7] = 0xBEFA4FA4;
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

// SHA224 hash function
static void
sha224_hash(struct sha224_context *ctx, const uint8_t buffer[64])
{
	uint32_t W[64];
	uint32_t a, b, c, d, e, f, g, h;

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

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

	W[16] = W[ 0] + DELTA0(W[ 1]) + W[ 9] + DELTA1(W[14]);
	W[17] = W[ 1] + DELTA0(W[ 2]) + W[10] + DELTA1(W[15]);
	W[18] = W[ 2] + DELTA0(W[ 3]) + W[11] + DELTA1(W[16]);
	W[19] = W[ 3] + DELTA0(W[ 4]) + W[12] + DELTA1(W[17]);
	W[20] = W[ 4] + DELTA0(W[ 5]) + W[13] + DELTA1(W[18]);
	W[21] = W[ 5] + DELTA0(W[ 6]) + W[14] + DELTA1(W[19]);
	W[22] = W[ 6] + DELTA0(W[ 7]) + W[15] + DELTA1(W[20]);
	W[23] = W[ 7] + DELTA0(W[ 8]) + W[16] + DELTA1(W[21]);
	W[24] = W[ 8] + DELTA0(W[ 9]) + W[17] + DELTA1(W[22]);
	W[25] = W[ 9] + DELTA0(W[10]) + W[18] + DELTA1(W[23]);
	W[26] = W[10] + DELTA0(W[11]) + W[19] + DELTA1(W[24]);
	W[27] = W[11] + DELTA0(W[12]) + W[20] + DELTA1(W[25]);
	W[28] = W[12] + DELTA0(W[13]) + W[21] + DELTA1(W[26]);
	W[29] = W[13] + DELTA0(W[14]) + W[22] + DELTA1(W[27]);
	W[30] = W[14] + DELTA0(W[15]) + W[23] + DELTA1(W[28]);
	W[31] = W[15] + DELTA0(W[16]) + W[24] + DELTA1(W[29]);
	W[32] = W[16] + DELTA0(W[17]) + W[25] + DELTA1(W[30]);
	W[33] = W[17] + DELTA0(W[18]) + W[26] + DELTA1(W[31]);
	W[34] = W[18] + DELTA0(W[19]) + W[27] + DELTA1(W[32]);
	W[35] = W[19] + DELTA0(W[20]) + W[28] + DELTA1(W[33]);
	W[36] = W[20] + DELTA0(W[21]) + W[29] + DELTA1(W[34]);
	W[37] = W[21] + DELTA0(W[22]) + W[30] + DELTA1(W[35]);
	W[38] = W[22] + DELTA0(W[23]) + W[31] + DELTA1(W[36]);
	W[39] = W[23] + DELTA0(W[24]) + W[32] + DELTA1(W[37]);
	W[40] = W[24] + DELTA0(W[25]) + W[33] + DELTA1(W[38]);
	W[41] = W[25] + DELTA0(W[26]) + W[34] + DELTA1(W[39]);
	W[42] = W[26] + DELTA0(W[27]) + W[35] + DELTA1(W[40]);
	W[43] = W[27] + DELTA0(W[28]) + W[36] + DELTA1(W[41]);
	W[44] = W[28] + DELTA0(W[29]) + W[37] + DELTA1(W[42]);
	W[45] = W[29] + DELTA0(W[30]) + W[38] + DELTA1(W[43]);
	W[46] = W[30] + DELTA0(W[31]) + W[39] + DELTA1(W[44]);
	W[47] = W[31] + DELTA0(W[32]) + W[40] + DELTA1(W[45]);
	W[48] = W[32] + DELTA0(W[33]) + W[41] + DELTA1(W[46]);
	W[49] = W[33] + DELTA0(W[34]) + W[42] + DELTA1(W[47]);
	W[50] = W[34] + DELTA0(W[35]) + W[43] + DELTA1(W[48]);
	W[51] = W[35] + DELTA0(W[36]) + W[44] + DELTA1(W[49]);
	W[52] = W[36] + DELTA0(W[37]) + W[45] + DELTA1(W[50]);
	W[53] = W[37] + DELTA0(W[38]) + W[46] + DELTA1(W[51]);
	W[54] = W[38] + DELTA0(W[39]) + W[47] + DELTA1(W[52]);
	W[55] = W[39] + DELTA0(W[40]) + W[48] + DELTA1(W[53]);
	W[56] = W[40] + DELTA0(W[41]) + W[49] + DELTA1(W[54]);
	W[57] = W[41] + DELTA0(W[42]) + W[50] + DELTA1(W[55]);
	W[58] = W[42] + DELTA0(W[43]) + W[51] + DELTA1(W[56]);
	W[59] = W[43] + DELTA0(W[44]) + W[52] + DELTA1(W[57]);
	W[60] = W[44] + DELTA0(W[45]) + W[53] + DELTA1(W[58]);
	W[61] = W[45] + DELTA0(W[46]) + W[54] + DELTA1(W[59]);
	W[62] = W[46] + DELTA0(W[47]) + W[55] + DELTA1(W[60]);
	W[63] = W[47] + DELTA0(W[48]) + W[56] + DELTA1(W[61]);

	// 63 rounds SHA224
	STEP(a, b, c, d, e, f, g, h, W[ 0], K[ 0]);
	STEP(a, b, c, d, e, f, g, h, W[ 1], K[ 1]);
	STEP(a, b, c, d, e, f, g, h, W[ 2], K[ 2]);
	STEP(a, b, c, d, e, f, g, h, W[ 3], K[ 3]);
	STEP(a, b, c, d, e, f, g, h, W[ 4], K[ 4]);
	STEP(a, b, c, d, e, f, g, h, W[ 5], K[ 5]);
	STEP(a, b, c, d, e, f, g, h, W[ 6], K[ 6]);
	STEP(a, b, c, d, e, f, g, h, W[ 7], K[ 7]);
	STEP(a, b, c, d, e, f, g, h, W[ 8], K[ 8]);
	STEP(a, b, c, d, e, f, g, h, W[ 9], K[ 9]);
	STEP(a, b, c, d, e, f, g, h, W[10], K[10]);
	STEP(a, b, c, d, e, f, g, h, W[11], K[11]);
	STEP(a, b, c, d, e, f, g, h, W[12], K[12]);
	STEP(a, b, c, d, e, f, g, h, W[13], K[13]);
	STEP(a, b, c, d, e, f, g, h, W[14], K[14]);
	STEP(a, b, c, d, e, f, g, h, W[15], K[15]);
	STEP(a, b, c, d, e, f, g, h, W[16], K[16]);
	STEP(a, b, c, d, e, f, g, h, W[17], K[17]);
	STEP(a, b, c, d, e, f, g, h, W[18], K[18]);
	STEP(a, b, c, d, e, f, g, h, W[19], K[19]);
	STEP(a, b, c, d, e, f, g, h, W[20], K[20]);
	STEP(a, b, c, d, e, f, g, h, W[21], K[21]);
	STEP(a, b, c, d, e, f, g, h, W[22], K[22]);
	STEP(a, b, c, d, e, f, g, h, W[23], K[23]);
	STEP(a, b, c, d, e, f, g, h, W[24], K[24]);
	STEP(a, b, c, d, e, f, g, h, W[25], K[25]);
	STEP(a, b, c, d, e, f, g, h, W[26], K[26]);
	STEP(a, b, c, d, e, f, g, h, W[27], K[27]);
	STEP(a, b, c, d, e, f, g, h, W[28], K[28]);
	STEP(a, b, c, d, e, f, g, h, W[29], K[29]);
	STEP(a, b, c, d, e, f, g, h, W[30], K[30]);
	STEP(a, b, c, d, e, f, g, h, W[31], K[31]);
	STEP(a, b, c, d, e, f, g, h, W[32], K[32]);
	STEP(a, b, c, d, e, f, g, h, W[33], K[33]);
	STEP(a, b, c, d, e, f, g, h, W[34], K[34]);
	STEP(a, b, c, d, e, f, g, h, W[35], K[35]);
	STEP(a, b, c, d, e, f, g, h, W[36], K[36]);
	STEP(a, b, c, d, e, f, g, h, W[37], K[37]);
	STEP(a, b, c, d, e, f, g, h, W[38], K[38]);
	STEP(a, b, c, d, e, f, g, h, W[39], K[39]);
	STEP(a, b, c, d, e, f, g, h, W[40], K[40]);
	STEP(a, b, c, d, e, f, g, h, W[41], K[41]);
	STEP(a, b, c, d, e, f, g, h, W[42], K[42]);
	STEP(a, b, c, d, e, f, g, h, W[43], K[43]);
	STEP(a, b, c, d, e, f, g, h, W[44], K[44]);
	STEP(a, b, c, d, e, f, g, h, W[45], K[45]);
	STEP(a, b, c, d, e, f, g, h, W[46], K[46]);
	STEP(a, b, c, d, e, f, g, h, W[47], K[47]);
	STEP(a, b, c, d, e, f, g, h, W[48], K[48]);
	STEP(a, b, c, d, e, f, g, h, W[49], K[49]);
	STEP(a, b, c, d, e, f, g, h, W[50], K[50]);
	STEP(a, b, c, d, e, f, g, h, W[51], K[51]);
	STEP(a, b, c, d, e, f, g, h, W[52], K[52]);
	STEP(a, b, c, d, e, f, g, h, W[53], K[53]);
	STEP(a, b, c, d, e, f, g, h, W[54], K[54]);
	STEP(a, b, c, d, e, f, g, h, W[55], K[55]);
	STEP(a, b, c, d, e, f, g, h, W[56], K[56]);
	STEP(a, b, c, d, e, f, g, h, W[57], K[57]);
	STEP(a, b, c, d, e, f, g, h, W[58], K[58]);
	STEP(a, b, c, d, e, f, g, h, W[59], K[59]);
	STEP(a, b, c, d, e, f, g, h, W[60], K[60]);
	STEP(a, b, c, d, e, f, g, h, W[61], K[61]);
	STEP(a, b, c, d, e, f, g, h, W[62], K[62]);
	STEP(a, b, c, d, e, f, g, h, W[63], K[63]);

	// SHA224 hash save
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

// SHA224 update function
// Caused be the addition of new data from calculate the hash
void
sha224_update(struct sha224_context *ctx, const void *message, uint32_t msglen)
{
	int n, len;

	n = ctx->nbits[0] & 0x3F;

	len = 64 - n;

	//Update bits length
	ctx->nbits[0] += msglen;
	
	// Detect and fix overflow
	if(ctx->nbits[0] < msglen)
		++ctx->nbits[1];
	
	if(msglen >= len) {
		
		// Calculate hash
		memcpy(ctx->buffer + n, message, len);
		message += len;
		msglen -= len;
		
		sha224_hash(ctx, ctx->buffer);

		// Calculate hash of the remaining messages
		while(msglen >= 64) {
			sha224_hash(ctx, message);
			message += 64;
			msglen -= 64;
		}

		n = 0;
	}

	// Save message remaining bytes of the buffer
	if(msglen >= 0)
		memcpy(ctx->buffer + n, message, msglen);
}

// Get the SHA224 hash of the message
// SHA224 hash located in array digest
void
sha224_final(struct sha224_context *ctx, uint8_t digest[28])
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

	sha224_update(ctx, sha224pad, npad);
	sha224_update(ctx, nb, 8);

	uint32_to_bytes(digest, ctx->state, 7);
}

