/*
 * SHA224 - US Secure Hash Algorithm Version 2 (RFC 4634).
 * Author SHA2 algorithm - NSA and NIST.
 * Hash size - 224 bits
*/

#ifndef SHA224_H
#define SHA224_H

/*
 * SHA224 algorithm context
 * nbits - number bit of the input message
 * state - 160 bits hash of the input message
 * buffer - 512 bits input message
*/
struct sha224_context {
	uint32_t nbits[2];
	uint32_t state[8];
	uint8_t buffer[64];
};

void sha224_init(struct sha224_context *ctx);

void sha224_update(struct sha224_context *ctx, const void *message, uint32_t msglen);

void sha224_final(struct sha224_context *ctx, uint8_t digest[28]);

#endif /* SHA224_H */
