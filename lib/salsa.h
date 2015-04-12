/* 
 * This library implements the SALSA20 algorithm
 * Developer - Daniel J. Bernstein.
 * SALSA20 - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/.
*/

#ifndef SALSA_H
#define SALSA_H

/* 
 * Salsa context
 * keylen - chiper key length in bytes
 * ivlen - vector initialization length in bytes
 * key - chiper key
 * iv - 16-byte array with a unique number. 8 bytes are filled by the user
 * x - intermediate array
*/
struct salsa_context {
	int keylen;
	int ivlen;
	uint8_t key[32];
	uint8_t iv[16];
	uint32_t x[16];
};

void salsa_init(struct salsa_context *ctx);

int salsa_set_key_and_iv(struct salsa_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[8], const int ivlen);

void salsa_encrypt(struct salsa_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void salsa_decrypt(struct salsa_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void salsa_test_vectors(struct salsa_context *ctx);

#endif
