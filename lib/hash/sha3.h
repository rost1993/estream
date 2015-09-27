/*
 * SHA3 - US Secure Hash Algorithm Version 3, 2008 year.
 * Author SHA3 algorithm - Joan Daemen, Guido Bertoni, Michael Peeters and Gilles Van Assche.
 * Hash size - 224, 256, 384, 512.
*/

#ifndef SHA3_H
#define SHA3_H

/*
 * SHA3 algorithm context
 * state - 1600 bits output state (Hash)
 * buffer - 1152 input message
 * hash_size - hash size in bytes (28, 32, 48, 64)
 * nbytes - number of bytes in the buffer
 * r - SHA3 constant, depends on the size of the hash
*/
struct sha3_context {
	uint64_t state[25];
	uint8_t buffer[144];
	int hash_size;
	int nbytes;
	int r;
};

// SHA3 initialization function
// hash_size - the size in bits of the hash
void sha3_init(struct sha3_context *ctx, int hash_size);

// SHA3 update function
// msglen - the size in bytes of the message
void sha3_update(struct sha3_context *ctx, void *message, uint32_t msglen);

// SHA3 final function
// digest - the pointer of the hash
void sha3_final(struct sha3_context *ctx, uint8_t *digest);

#endif /* SHA3_H */
