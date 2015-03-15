/* This library implements the Trivium algorithm
 * Author - Christophe De Canniere and Bart Preneel, Katholieke Universiteit Leuven
 * Trivium - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/
*/

#ifndef TRIVIUM_H_
#define TRIVIUM_H_

struct trivium_context;

struct trivium_context *trivium_context_new(void);
void trivium_context_free(struct trivium_context **ctx);

int trivium_set_key_and_iv(struct trivium_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[10], const int ivlen);

void trivium_encrypt(struct trivium_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void trivium_decrypt(struct trivium_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void trivium_test_vectors(struct trivium_context *ctx);

#endif
