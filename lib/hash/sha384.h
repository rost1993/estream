/*
 * SHA384 - US Secure Hash Algorithm Version 2 (RFC 4634).
 * Author SHA2 algorithm - NSA and NIST.
 * Hash size - 384 bits
*/

#ifndef SHA384_H
#define SHA384_H

/*
 * SHA384 algorithm context
 * nbits - number bit of the input message
 * state - 512 bits hash of the input message
 * buffer - 512 bits inpuf message
*/
struct sha384_context {
	uint32_t nbits[2];
	uint64_t state[8];
	uint8_t buffer[128];
};

void sha384_init(struct sha384_context *ctx);

void sha384_update(struct sha384_context *ctx, const void *message, uint32_t msglen);

void sha384_final(struct sha384_context *ctx, uint8_t digest[48]);

#endif /* SHA384_H */
