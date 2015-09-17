/*
 * SHA512 - US Secure Hash Algorithm Version 2 (RFC 4634).
 * Author SHA2 algorithm - NSA and NIST.
 * Hash size - 512 bits
*/

#ifndef SHA512_H
#define SHA512_H

/*
 * SHA512 algorithm context
 * nbits - number bit of the input message
 * state - 512 bits hash of the input message
 * buffer - 512 bits inpuf message
*/
struct sha512_context {
	uint32_t nbits[2];
	uint64_t state[8];
	uint8_t buffer[128];
};

void sha512_init(struct sha512_context *ctx);

void sha512_update(struct sha512_context *ctx, const void *message, uint32_t msglen);

void sha512_final(struct sha512_context *ctx, uint8_t digest[64]);

#endif /* SHA512_H */
