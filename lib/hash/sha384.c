/*
 * This program implements the SHA384 hash functions RFC 4634.
 * Author SHA384 algorithm - NSA and NIST.
 *
 * Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * 10.09.2015, <rostislav-gashin@yandex.ru>
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha384.h"
#include "../macro.h"

// Functions for the SHA384 algorithm
#define CH(x, y, z)	((x & y) ^ ((~x) & z))
#define MAJ(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
#define SIGMA0(x)	(ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SIGMA1(x)	(ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define DELTA0(x)	(ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR(x, 7))
#define DELTA1(x)	(ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHR(x, 6))

/*
 * STEP - main step SHA384 conversion
 * a, b, c, d, e, f, g, h - state 64-bit word
 * W - 64-bit word
 * K - SHA384 constant
*/
#define STEP(a, b, c, d, e, f, g, h, W, K) {		\
	uint64_t temp1, temp2;				\
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

// Single bit (byte 0x80), other 127 bytes are zero
const uint8_t sha384pad[128] = { 0x80 };

// SHA384 80 constant
static const uint64_t K[80] = { 
	0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
	0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
	0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
	0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
	0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
	0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
	0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
	0xC6E00BF33dA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
	0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380d139D95B3DF,
	0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
	0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
	0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
	0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
	0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
	0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
	0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
	0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
	0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
	0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
	0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817 };

// Initialization function
void
sha384_init(struct sha384_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->state[0] = 0xCBBB9D5DC1059ED8;
	ctx->state[1] = 0x629A292A367CD507;
	ctx->state[2] = 0x9159015A3070DD17;
	ctx->state[3] = 0x152FECD8F70E5939;
	ctx->state[4] = 0x67332667FFC00B31;
	ctx->state[5] = 0x8EB44A8768581511;
	ctx->state[6] = 0xDB0C2E0D64F98FA7;
	ctx->state[7] = 0x47B5481DBEFA4FA4;
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

// 64-byte array is transformed into 8-byte array
static void
uint64_to_bytes(uint8_t *out, uint64_t *in, const int n)
{
	int x, y;

	for(x = y = 0; y < n; y++) {
		out[x++] = (in[y] >> 56) & 0xFF;
		out[x++] = (in[y] >> 48) & 0xFF;
		out[x++] = (in[y] >> 40) & 0xFF;
		out[x++] = (in[y] >> 32) & 0xFF;
		out[x++] = (in[y] >> 24) & 0xFF;
		out[x++] = (in[y] >> 16) & 0xFF;
		out[x++] = (in[y] >> 8) & 0xFF;
		out[x++] = in[y] & 0xFF;
	}
}

// SHA384 hash function
static void
sha384_hash(struct sha384_context *ctx, const uint8_t buffer[128])
{
	uint64_t W[80];
	uint64_t a, b, c, d, e, f, g, h;

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	W[ 0] = U8TO64_BIG(buffer);
	W[ 1] = U8TO64_BIG(buffer + 8);
	W[ 2] = U8TO64_BIG(buffer + 16);
	W[ 3] = U8TO64_BIG(buffer + 24);
	W[ 4] = U8TO64_BIG(buffer + 32);
	W[ 5] = U8TO64_BIG(buffer + 40);
	W[ 6] = U8TO64_BIG(buffer + 48);
	W[ 7] = U8TO64_BIG(buffer + 56);
	W[ 8] = U8TO64_BIG(buffer + 64);
	W[ 9] = U8TO64_BIG(buffer + 72);
	W[10] = U8TO64_BIG(buffer + 80);
	W[11] = U8TO64_BIG(buffer + 88);
	W[12] = U8TO64_BIG(buffer + 96);
	W[13] = U8TO64_BIG(buffer + 104);
	W[14] = U8TO64_BIG(buffer + 112);
	W[15] = U8TO64_BIG(buffer + 120);

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
	W[64] = W[48] + DELTA0(W[49]) + W[57] + DELTA1(W[62]);
	W[65] = W[49] + DELTA0(W[50]) + W[58] + DELTA1(W[63]);
	W[66] = W[50] + DELTA0(W[51]) + W[59] + DELTA1(W[64]);
	W[67] = W[51] + DELTA0(W[52]) + W[60] + DELTA1(W[65]);
	W[68] = W[52] + DELTA0(W[53]) + W[61] + DELTA1(W[66]);
	W[69] = W[53] + DELTA0(W[54]) + W[62] + DELTA1(W[67]);
	W[70] = W[54] + DELTA0(W[55]) + W[63] + DELTA1(W[68]);
	W[71] = W[55] + DELTA0(W[56]) + W[64] + DELTA1(W[69]);
	W[72] = W[56] + DELTA0(W[57]) + W[65] + DELTA1(W[70]);
	W[73] = W[57] + DELTA0(W[58]) + W[66] + DELTA1(W[71]);
	W[74] = W[58] + DELTA0(W[59]) + W[67] + DELTA1(W[72]);
	W[75] = W[59] + DELTA0(W[60]) + W[68] + DELTA1(W[73]);
	W[76] = W[60] + DELTA0(W[61]) + W[69] + DELTA1(W[74]);
	W[77] = W[61] + DELTA0(W[62]) + W[70] + DELTA1(W[75]);
	W[78] = W[62] + DELTA0(W[63]) + W[71] + DELTA1(W[76]);
	W[79] = W[63] + DELTA0(W[64]) + W[72] + DELTA1(W[77]);

	// 80 rounds SHA384
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
	STEP(a, b, c, d, e, f, g, h, W[64], K[64]);
	STEP(a, b, c, d, e, f, g, h, W[65], K[65]);
	STEP(a, b, c, d, e, f, g, h, W[66], K[66]);
	STEP(a, b, c, d, e, f, g, h, W[67], K[67]);
	STEP(a, b, c, d, e, f, g, h, W[68], K[68]);
	STEP(a, b, c, d, e, f, g, h, W[69], K[69]);
	STEP(a, b, c, d, e, f, g, h, W[70], K[70]);
	STEP(a, b, c, d, e, f, g, h, W[71], K[71]);
	STEP(a, b, c, d, e, f, g, h, W[72], K[72]);
	STEP(a, b, c, d, e, f, g, h, W[73], K[73]);
	STEP(a, b, c, d, e, f, g, h, W[74], K[74]);
	STEP(a, b, c, d, e, f, g, h, W[75], K[75]);
	STEP(a, b, c, d, e, f, g, h, W[76], K[76]);
	STEP(a, b, c, d, e, f, g, h, W[77], K[77]);
	STEP(a, b, c, d, e, f, g, h, W[78], K[78]);
	STEP(a, b, c, d, e, f, g, h, W[79], K[79]);

	// SHA384 hash save
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

// SHA384 update function
// Caused be the addition of new data from calculate the hash
void
sha384_update(struct sha384_context *ctx, const void *message, uint32_t msglen)
{
	int n, len;

	n = ctx->nbits[0] & 0x7F;

	len = 128 - n;

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

		sha384_hash(ctx, ctx->buffer);

		// Calculate hash of the remaining messages
		while(msglen >= 128) {
			sha384_hash(ctx, message);
			message += 128;
			msglen -= 128;
		}

		n = 0;
	}

	// Save message remaining bytes of the buffer
	if(msglen >= 0)
		memcpy(ctx->buffer + n, message, msglen);
}

// Get the SHA384 hash of the message
// SHA384 hash located in array digest
void
sha384_final(struct sha384_context *ctx, uint8_t digest[48])
{
	uint32_t nbits[2];
	uint8_t nb[16];
	int n, npad;

	n = ctx->nbits[0] & 0x7F;
	npad = ((n < 112) ? 112 : 240) - n;

	nbits[0] = ctx->nbits[1] << 3;
	nbits[0] += ctx->nbits[0] >> 29;
	nbits[1] = ctx->nbits[0] << 3;

	memset(nb, 0, sizeof(nb));

	uint32_to_bytes(nb + 8, nbits, 1);
	uint32_to_bytes(nb + 12, nbits + 1, 1);

	sha384_update(ctx, sha384pad, npad);
	sha384_update(ctx, nb, 16);

	uint64_to_bytes(digest, ctx->state, 6);
}

