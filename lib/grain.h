/*
 * This library implements the Grain-128 algorithm
 * Developer - M. Hell, T. Johansson, A. Maximov. Lund University, Sweden.
 * Grain-128 - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/.
*/

#ifndef GRAIN_H_
#define GRAIN_H_

struct grain_context;

struct grain_context *grain_context_new(void);
void grain_context_free(struct grain_context **ctx);

int grain_set_key_and_iv(struct grain_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[12]);

void grain_encrypt(struct grain_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void grain_decrypt(struct grain_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void grain_test_vectors(struct grain_context *ctx);

#endif
