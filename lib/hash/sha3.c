/*
 * This program implements the SHA3 hash function.
 * Author SHA3 algorithm - Guido Bertoni, Joan Daemen, Michael Peeters and Gilles Van Assche.
 *
 * Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * 27.09.2015, <rostislav-gashin@yandex.ru>
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha3.h"
#include "../macro.h"

// SHA3 rotate index
static const uint64_t ROTATE[25] = {
	 0, 36,  3, 41, 18,
	 1, 44, 10, 45,  2,
	62,  6, 43, 15, 61,
	28, 55, 25, 21, 56,
	27, 20, 39,  8, 14 
};

// SHA3 array of the constant, RC[i] XOR A[0] end of the round
static const uint64_t RC[24] = {
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008 
};

// SHA3 initialization function
// hash_size - the size in bits of the hash
void
sha3_init(struct sha3_context *ctx, int hash_size)
{
	memset(ctx, 0, sizeof(*ctx));

	// Fill the sha3_context depending on the size of the hash
	switch(hash_size) {
	case 224 : ctx->hash_size = 28;
		   ctx->r = 144;
		   break;
	case 256 : ctx->hash_size = 32;
		   ctx->r = 136;
		   break;
	case 384 : ctx->hash_size = 48;
		   ctx->r = 104;
		   break;
	case 512 : ctx->hash_size = 64;
		   ctx->r = 72;
		   break;
	default : ctx->hash_size = 64;
		  ctx->r = 72;
		  break;
	}
}

// SHA3 hash function
static void
sha3_hash(struct sha3_context *ctx, const uint8_t buffer[144])
{
	uint64_t C[5], D[5], B[25], A[25];
	int i;

	// Copy state of the array A
	memcpy(A, ctx->state, sizeof(A));

	A[ 0] ^= U8TO64_LITTLE(buffer + 0);
	A[ 5] ^= U8TO64_LITTLE(buffer + 8);
	A[10] ^= U8TO64_LITTLE(buffer + 16);
	A[15] ^= U8TO64_LITTLE(buffer + 24);
	A[20] ^= U8TO64_LITTLE(buffer + 32);
	A[ 1] ^= U8TO64_LITTLE(buffer + 40);
	A[ 6] ^= U8TO64_LITTLE(buffer + 48);
	A[11] ^= U8TO64_LITTLE(buffer + 56);
	A[16] ^= U8TO64_LITTLE(buffer + 64);
	
	if(ctx->hash_size < 64) {
		A[21] ^= U8TO64_LITTLE(buffer + 72);
		A[ 2] ^= U8TO64_LITTLE(buffer + 80);
		A[ 7] ^= U8TO64_LITTLE(buffer + 88);
		A[12] ^= U8TO64_LITTLE(buffer + 96);
	
		if(ctx->hash_size < 48) {
			A[17] ^= U8TO64_LITTLE(buffer + 104);
			A[21] ^= U8TO64_LITTLE(buffer + 112);
			A[ 3] ^= U8TO64_LITTLE(buffer + 120);
			A[ 8] ^= U8TO64_LITTLE(buffer + 128);
		}
	
		if(ctx->hash_size < 32)
			A[13] ^= U8TO64_LITTLE(buffer + 136);
	}

	// SHA3 24 round
	for(i = 0; i < 24; i++) {
		C[0] = A[ 0] ^ A[ 1] ^ A[ 2] ^ A[ 3] ^ A[ 4];
		C[1] = A[ 5] ^ A[ 6] ^ A[ 7] ^ A[ 8] ^ A[ 9];
		C[2] = A[10] ^ A[11] ^ A[12] ^ A[13] ^ A[14];
		C[3] = A[15] ^ A[16] ^ A[17] ^ A[18] ^ A[19];
		C[4] = A[20] ^ A[21] ^ A[22] ^ A[23] ^ A[24];
	
		D[0] = C[4] ^ ROTL64(C[1], 1);
		D[1] = C[0] ^ ROTL64(C[2], 1);
		D[2] = C[1] ^ ROTL64(C[3], 1);
		D[3] = C[2] ^ ROTL64(C[4], 1);
		D[4] = C[3] ^ ROTL64(C[0], 1);

		A[ 0] ^= D[0];
		A[ 1] ^= D[0];
		A[ 2] ^= D[0];
		A[ 3] ^= D[0];
		A[ 4] ^= D[0];
		A[ 5] ^= D[1];
		A[ 6] ^= D[1];
		A[ 7] ^= D[1];
		A[ 8] ^= D[1];
		A[ 9] ^= D[1];
		A[10] ^= D[2];
		A[11] ^= D[2];
		A[12] ^= D[2];
		A[13] ^= D[2];
		A[14] ^= D[2];
		A[15] ^= D[3];
		A[16] ^= D[3];
		A[17] ^= D[3];
		A[18] ^= D[3];
		A[19] ^= D[3];
		A[20] ^= D[4];
		A[21] ^= D[4];
		A[22] ^= D[4];
		A[23] ^= D[4];
		A[24] ^= D[4];

		B[ 0] = ROTL64(A[ 0], ROTATE[ 0]);
		B[ 8] = ROTL64(A[ 1], ROTATE[ 1]);
		B[11] = ROTL64(A[ 2], ROTATE[ 2]);
		B[19] = ROTL64(A[ 3], ROTATE[ 3]);
		B[22] = ROTL64(A[ 4], ROTATE[ 4]);
		B[ 2] = ROTL64(A[ 5], ROTATE[ 5]);
		B[ 5] = ROTL64(A[ 6], ROTATE[ 6]);
		B[13] = ROTL64(A[ 7], ROTATE[ 7]);
		B[16] = ROTL64(A[ 8], ROTATE[ 8]);
		B[24] = ROTL64(A[ 9], ROTATE[ 9]);
		B[ 4] = ROTL64(A[10], ROTATE[10]);
		B[ 7] = ROTL64(A[11], ROTATE[11]);
		B[10] = ROTL64(A[12], ROTATE[12]);
		B[18] = ROTL64(A[13], ROTATE[13]);
		B[21] = ROTL64(A[14], ROTATE[14]);
		B[ 1] = ROTL64(A[15], ROTATE[15]);
		B[ 9] = ROTL64(A[16], ROTATE[16]);
		B[12] = ROTL64(A[17], ROTATE[17]);
		B[15] = ROTL64(A[18], ROTATE[18]);
		B[23] = ROTL64(A[19], ROTATE[19]);
		B[ 3] = ROTL64(A[20], ROTATE[20]);
		B[ 6] = ROTL64(A[21], ROTATE[21]);
		B[14] = ROTL64(A[22], ROTATE[22]);
		B[17] = ROTL64(A[23], ROTATE[23]);
		B[20] = ROTL64(A[24], ROTATE[24]);

		A[ 0] = B[ 0] ^ (~B[ 5] & B[10]);
		A[ 1] = B[ 1] ^ (~B[ 6] & B[11]);
		A[ 2] = B[ 2] ^ (~B[ 7] & B[12]);
		A[ 3] = B[ 3] ^ (~B[ 8] & B[13]);
		A[ 4] = B[ 4] ^ (~B[ 9] & B[14]);
		A[ 5] = B[ 5] ^ (~B[10] & B[15]);
		A[ 6] = B[ 6] ^ (~B[11] & B[16]);
		A[ 7] = B[ 7] ^ (~B[12] & B[17]);
		A[ 8] = B[ 8] ^ (~B[13] & B[18]);
		A[ 9] = B[ 9] ^ (~B[14] & B[19]);
		A[10] = B[10] ^ (~B[15] & B[20]);
		A[11] = B[11] ^ (~B[16] & B[21]);
		A[12] = B[12] ^ (~B[17] & B[22]);
		A[13] = B[13] ^ (~B[18] & B[23]);
		A[14] = B[14] ^ (~B[19] & B[24]);
		A[15] = B[15] ^ (~B[20] & B[ 0]);
		A[16] = B[16] ^ (~B[21] & B[ 1]);
		A[17] = B[17] ^ (~B[22] & B[ 2]);
		A[18] = B[18] ^ (~B[23] & B[ 3]);
		A[19] = B[19] ^ (~B[24] & B[ 4]);
		A[20] = B[20] ^ (~B[ 0] & B[ 5]);
		A[21] = B[21] ^ (~B[ 1] & B[ 6]);
		A[22] = B[22] ^ (~B[ 2] & B[ 7]);
		A[23] = B[23] ^ (~B[ 3] & B[ 8]);
		A[24] = B[24] ^ (~B[ 4] & B[ 9]);

		A[0] ^= RC[i];
	}

	// SHA3 hash save
	memcpy(ctx->state, A, sizeof(A));
}

// SHA3 padding function
static void
sha3_padding(struct sha3_context *ctx, uint8_t buffer[144])
{
	int n;

	n = ctx->nbytes;

	// If add 1 byte -> padding 0x81
	if(ctx->nbytes + 1 == ctx->r) {
		buffer[ctx->r-1] = 0x81;
		return;
	}

	// Add 0x01 in the end message
	buffer[n] = 0x01;

	// Add 0x00 in the message
	memset(buffer + (n+1), 0, ctx->r - n - 2);

	// Add 0x80 in the last bytes message
	buffer[ctx->r-1] = 0x80;
}

// SHA3 update function
// msglen - the size in bytes of the message
void
sha3_update(struct sha3_context *ctx, void *message, uint32_t msglen)
{
	int n, len, r;

	n = ctx->nbytes;
	r = ctx->r;
	len = r - n;

	// Check buffer empty
	if(len == 0) {
		len = r;
		n = 0;
	}

	if(msglen >= len) {
	
		// Calculate hash
		memcpy(ctx->buffer + n, message, len);
		message += len;
		msglen -= len;

		sha3_hash(ctx, ctx->buffer);

		// Calculate hash of the remaining messages
		while(msglen >= r) {
			sha3_hash(ctx, message);
			message += len;
			msglen -= len;
		}

		n = 0;
		ctx->nbytes = r;
	}

	// The number of bytes in the buffer
	ctx->nbytes += msglen;

	// If number of bytes > R, then nbytes = msglen 
	if(ctx->nbytes > r)
		ctx->nbytes = msglen;

	// Save message remaining bytes of the buffer
	if(msglen > 0)
		memcpy(ctx->buffer + n, message, msglen);
}

// SHA3 final function
// digest - the pointer of the hash
void
sha3_final(struct sha3_context *ctx, uint8_t *digest)
{
	// Padding message
	if((ctx->r - ctx->nbytes) > 0) {
		sha3_padding(ctx, ctx->buffer);
		sha3_hash(ctx, ctx->buffer);
	}

	// Save hash of the digest
	U64TO8_LITTLE((digest +  0), ctx->state[ 0]);
	U64TO8_LITTLE((digest +  8), ctx->state[ 5]);
	U64TO8_LITTLE((digest + 16), ctx->state[10]);

	// Special for hash size 224 bits
	if(ctx->hash_size == 28) {
		U32TO8_LITTLE((digest + 24), (uint32_t)(ctx->state[15]));
	} 
	else {
		U64TO8_LITTLE((digest + 24), ctx->state[15]);
	
		if(ctx->hash_size > 32) {
			U64TO8_LITTLE((digest + 32), ctx->state[20]);
			U64TO8_LITTLE((digest + 40), ctx->state[ 1]);
		}
	
		if(ctx->hash_size > 48) {
			U64TO8_LITTLE((digest + 48), ctx->state[ 6]);
			U64TO8_LITTLE((digest + 56), ctx->state[11]);
		}
	}
}

