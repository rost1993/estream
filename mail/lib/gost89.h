/*
 * This library implements the GOST 28147-89 algorithm
 * Developer - the 8th KGB
 * The GOST 28147-89 - the cryptographic standard of Russia
*/

#ifndef GOST89_H
#define GOST89_H

/*
 * GOST89 context
 * keylen - chiper key length in bytes
 * key - chiper key
 * gamma - array of gamma
*/
struct gost89_context {
	int keylen;
	uint32_t key[8];
	uint32_t gamma[2];
};

int gost89_set_key_and_gamma(struct gost89_context *ctx, const uint8_t *key, const int keylen, const uint8_t gamma[8]);

void gost89_encrypt(struct gost89_context *ctx, uint32_t *block);
void gost89_decrypt(struct gost89_context *ctx, uint32_t *block);

void gost89_gamma_crypt(struct gost89_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

#endif /* GOST89_H */
