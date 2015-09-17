/*
 * SHA256 - US Secure Hash Algorithm Version 2 (RFC 4634).
 * Author SHA2 algorithm - NSA and NIST.
 * Hash size - 256 bits
*/

#ifndef SHA256_H
#define SHA256_H

/*
 * SHA256 algorithm context
 * nbits - number bit of the input message
 * state - 160 bits hash of the input message
 * buffer - 512 bits input message
*/
struct sha256_context {
	uint32_t nbits[2];
	uint32_t state[8];
	uint8_t buffer[64];
};

void sha256_init(struct sha256_context *ctx);

void sha256_update(struct sha256_context *ctx, const void *message, uint32_t msglen);

void sha256_final(struct sha256_context *ctx, uint8_t digest[32]);

#endif /* SHA256_H */
