/*
 * MD5 hash function (RFC 1321).
 * Author MD5 algorithm - Ronald Linn Rivest, Massachusetts Institute of Technology.
 * Hash size - 128 bits
*/

#ifndef MD5_H
#define MD5_H

/*
 * MD5 algorithm context
 * nbits - number bit of the message
 * state - 128 bits hash of the input message
 * buffer - 512 bits input message
*/

struct md5_context {
	uint32_t nbits[2];
	uint32_t state[4];
	uint8_t buffer[64];
};

void md5_init(struct md5_context *ctx);

void md5_update(struct md5_context *ctx, const void *message, uint32_t msglen);

void md5_final(struct md5_context *ctx, uint8_t digest[16]);

#endif /* MD5_H */
