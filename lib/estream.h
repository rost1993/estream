/*
 * This library implements the 7 algorithm eSTREAM project.
 * Algorithms: SALSA, RABBIT, HC128, SOSEMANUK, GRAIN, TRIVIUM, MICKEY 2.0.
 * Home page eSTREAM project - http://www.ecrypt.eu.org/stream/.
*/

#ifndef ESTREAM_H
#define ESTREAM_H

struct salsa_context;
struct rabbit_context;
struct hc128_context;
struct sosemanuk_context;
struct grain_context;
struct mickey_context;
struct trivium_context;

struct salsa_context *salsa_context_new(void);
struct rabbit_context *rabbit_context_new(void);
struct hc128_context *hc128_context_new(void);
struct sosemanuk_context *sosemanuk_context_new(void);
struct grain_context *grain_context_new(void);
struct mickey_context *mickey_context_new(void);
struct trivium_context *trivium_context_new(void);

void salsa_context_free(struct salsa_context **ctx);
void rabbit_context_free(struct rabbit_context **ctx);
void hc128_context_free(struct hc128_context **ctx);
void sosemanuk_context_free(struct sosemanuk_context **ctx);
void grain_context_free(struct grain_context **ctx);
void mickey_context_free(struct mickey_context **ctx);
void trivium_context_free(struct trivium_context **ctx);

int salsa_set_key_and_iv(struct salsa_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[8], int ivlen);
int rabbit_set_key_and_iv(struct rabbit_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[8], int ivlen);
int hc128_set_key_and_iv(struct hc128_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[16], int ivlen);
int sosemanuk_set_key_and_iv(struct sosemanuk_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[16], int ivlen);
int grain_set_key_and_iv(struct grain_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[12], int ivlen);
int mickey_set_key_and_iv(struct mickey_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[10], int ivlen);
int trivium_set_key_and_iv(struct trivium_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[10], int ivlen);

void salsa_encrypt(struct salsa_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void rabbit_encrypt(struct rabbit_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void hc128_encrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void sosemanuk_encrypt(struct sosemanuk_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void grain_encrypt(struct grain_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void mickey_encrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out);
void trivium_encrypt(struct trivium_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void salsa_decrypt(struct salsa_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void rabbit_decrypt(struct rabbit_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void hc128_decrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void sosemanuk_decrypt(struct sosemanuk_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void grain_decrypt(struct grain_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void mickey_decrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out);
void trivium_decrypt(struct trivium_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void salsa_test_vectors(struct salsa_context *ctx);
void rabbit_test_vectors(struct rabbit_context *ctx);
void hc128_test_vectors(struct hc128_context *ctx);
void sosemanuk_test_vectors(struct sosemanuk_context *ctx);
void grain_test_vectors(struct grain_context *ctx);
void mickey_test_vectors(struct mickey_context *ctx);
void trivium_test_vectors(struct trivium_context *ctx);

#endif
