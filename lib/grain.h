/*
 * This library implements the Grain-128 algorithm
 * Developer - M. Hell, T. Johansson, A. Maximov. Lund University, Sweden.
 * Grain-128 - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/.
*/

#ifndef GRAIN_H
#define GRAIN_H

/*
 * Grain context
 * keylen - chiper key length in bits
 * ivlen - vector initialization length in bits
 * key - chiper key
 * iv - initialization vector
 * b - register NFSR
 * s - register LFSR
*/
struct grain_context {
	int keylen;
	int ivlen;
	uint8_t key[16];
	uint8_t iv[12];
	uint8_t b[128];
	uint8_t s[128];
};

void grain_init(struct grain_context *ctx);

int grain_set_key_and_iv(struct grain_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[12], const int ivlen);

void grain_encrypt(struct grain_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void grain_decrypt(struct grain_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void grain_test_vectors(struct grain_context *ctx);

#endif
