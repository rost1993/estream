/* 
 * This library implements the RABBIT-128 algorithm
 * Developer - Martin Boesgaard, Mette Vesterager, Thomas Christensen, Erik Zanner
 * Company CRYPTICO A/S Fruebjergvei 3, Copenhagen, Denmark
 * RABBIT-128 - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/.
*/

#ifndef RABBIT_H
#define RABBIT_H

/* 
 * RABBIT-128 context
 * keylen - chiper key length in bytes
 * ivlen - vector initializaton length in bytes
 * key - chiper key
 * iv - initialization vector
 * x - the state variables
 * c - the counter system  
 * carry - 513 bit, the internal state
*/
struct rabbit_context {
	int keylen;
	int ivlen;
	uint8_t key[16];
	uint8_t iv[8];
	uint32_t x[8];
	uint32_t c[8];
	uint32_t carry;
};

int rabbit_set_key_and_iv(struct rabbit_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[8], const int ivlen);

void rabbit_crypt(struct rabbit_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void rabbit_test_vectors(struct rabbit_context *ctx);

#endif
