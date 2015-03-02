/* 
 * This library implements the SALSA20 algorithm
 * Developer - Daniel J. Bernstein.
 * SALSA20 - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/.
*/

#ifndef SALSA_H_
#define SALSA_H_

struct salsa_context;

struct salsa_context *salsa_context_new(void);
void salsa_context_free(struct salsa_context **ctx);

int salsa_set_key_and_iv(struct salsa_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[8]);

void salsa_encrypt(struct salsa_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void salsa_decrypt(struct salsa_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void salsa_test_vectors(struct salsa_context *ctx);

#endif
