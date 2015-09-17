/*
 * SHA1 - US Secure Hash Algorithm 1 (RFC 3174).
 * Author SHA1 algorithm - NSA and NIST.
 * Hash size - 160 bits
*/

#ifndef SHA1_H
#define SHA1_H

/*
 * SHA1 algorithm context
 * nbits - number bit of the input message
 * state - 160 bits hash of the input message
 * buffer - 512 bits input message
*/
struct sha1_context {
	uint32_t nbits[2];
	uint32_t state[5];
	uint8_t buffer[64];
};

void sha1_init(struct sha1_context *ctx);

void sha1_update(struct sha1_context *ctx, const void *message, uint32_t msglen);

void sha1_final(struct sha1_context *ctx, uint8_t digest[20]);

#endif /* SHA1_H */
