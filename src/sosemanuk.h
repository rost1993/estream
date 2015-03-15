/*
 * This library implements the stream cipher Sosemanuk

 * Author - C. Berbain, O. Billet, A. Canteaut, N. Courtois, H. Gilbert, L. Goubin,
 * A. Gouget, L. Granboulan, C. Lauradoux, M. Minier, T. Pornin and H. Sibert
 * Sosemanuk - the winner eSTREAM Project. Home page - http://www.ecrypt.eu.org/stream/
*/

#ifndef SOSEMANUK_H_
#define SOSEMANUK_H_

struct sosemanuk_context;

struct sosemanuk_context *sosemanuk_context_new(void);
void sosemanuk_context_free(struct sosemanuk_context **ctx);

int sosemanuk_set_key_and_iv(struct sosemanuk_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[16], const int ivlen);

void sosemanuk_encrypt(struct sosemanuk_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void sosemanuk_decrypt(struct sosemanuk_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void sosemanuk_test_vectors(struct sosemanuk_context *ctx);

#endif
