/* 
 * This library implements the Trivium algorithm
 * Author - Christophe De Canniere and Bart Preneel, Katholieke Universiteit Leuven
 * Trivium - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/
*/

#ifndef TRIVIUM_H
#define TRIVIUM_H

/* 
 * Trivium context 
 * keylen - chiper key length in bytes
 * ivlen - vector initialization length in bytes
 * key - chiper key
 * iv - initialization vector
 * w - array of intermediate calculations
*/
struct trivium_context {
	int keylen;
	int ivlen;
	uint8_t key[10];
	uint8_t iv[10];
	uint32_t w[10];
};

int trivium_set_key_and_iv(struct trivium_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[10], const int ivlen);

void trivium_crypt(struct trivium_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void trivium_test_vectors(struct trivium_context *ctx);

#endif
