/*
 * This program provides an interface for testing algorithms HASH functions.
 * Makefile: Makefile_hash
 * Compile: make -f Makefile_hash
 * Example: ./estream -h or ./estream -a 1 -f 1.text or ./estream -t test_string
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <getopt.h>
#include "estream.h"

// Maximum bytes read of the file
#define READ_BYTES	1000

// Print the HASH
#define PRINT_DIGEST(digest, size) { 		\
	int i;					\
	for(i = 0; i < size; i++)		\
		printf("%02X", digest[i]);	\
	printf("\n");				\
}

static void hash_text(void *ctx, int alg, char *text, int size);
static void hash_file(void *ctx, int alg, char *file_name, int size);

// Union all structures HASH functions
union context {
	struct md5_context md5;
	struct sha1_context sha1;
	struct sha224_context sha224;
	struct sha256_context sha256;
	struct sha384_context sha384;
	struct sha512_context sha512;
	struct sha3_context sha3;
};

typedef void (*func_t)(void *ctx, const int alg, char *s, int size);
typedef void (*init_t)(void *ctx, ...);
typedef void (*update_t)(void *ctx, void *message, uint32_t msglen);
typedef void (*final_t)(void *ctx, uint8_t *digest);

// Pointer of the function HASH functions
func_t func[] = { (func_t)hash_text,
		  (func_t)hash_file };

init_t init[] = { (init_t)md5_init,
		  (init_t)sha1_init,
		  (init_t)sha224_init,
		  (init_t)sha256_init,
		  (init_t)sha384_init,
		  (init_t)sha512_init,
		  (init_t)sha3_init };

update_t update[] = { (update_t)md5_update,
		      (update_t)sha1_update,
		      (update_t)sha224_update,
		      (update_t)sha256_update,
		      (update_t)sha384_update,
		      (update_t)sha512_update,
		      (update_t)sha3_update };

final_t final[] = { (final_t)md5_final,
		    (final_t)sha1_final,
		    (final_t)sha224_final,
		    (final_t)sha256_final,
		    (final_t)sha384_final,
		    (final_t)sha512_final,
		    (final_t)sha3_final };

// Hash size
static const int hash_size[10] = { 16, 20, 28, 32, 48, 64, 28, 32, 48, 64 };

// Calculate the HASH of the text string
static void
hash_text(void *ctx, int alg, char *text, int size)
{
	uint8_t digest[hash_size[alg]];
	int tmp = alg;

	if(size != 0) {
		alg = 6;
		init[alg](ctx, size);
	}
	else
		init[alg](ctx);

	update[alg](ctx, text, strlen(text));
	final[alg](ctx, digest);

	PRINT_DIGEST(digest, hash_size[tmp]);
}

// Calculate the HASH of the file
static void
hash_file(void *ctx, int alg, char *file_name, int size)
{
	FILE *fp;
	uint8_t digest[hash_size[alg]], buf[READ_BYTES];
	uint32_t byte;
	int tmp = alg;

	if((fp = fopen(file_name, "rb+")) == NULL) {
		printf("Error openning the file - %s!\n", file_name);
		return;
	}
	
	if(size != 0) {
		alg = 6;
		init[alg](ctx, size);
	}
	else
		init[alg](ctx);

	while((byte = fread(buf, 1, READ_BYTES, fp)) > 0)
		update[alg](ctx, buf, byte);

	fclose(fp);

	final[alg](ctx, digest);

	PRINT_DIGEST(digest, hash_size[tmp]);
}

// Manual of the program
static void
help(void)
{
	printf("\nThis program calculates the HASH functions!\n");
	printf("\nOptions:\n");
	printf("\t--help(-h) - reference manual\n");
	printf("\t--text(-t) - the string that needs the HASH to be calculated\n");
	printf("\t--file(-f) - the file name that needs the HASH to be calculated\n");
	printf("\t--algorithm(-a) - selection type HASH\n");
	printf("\t\t0 - MD5 hash\n\t\t1 - SHA1 hash\n\t\t2 - SHA224 hash\n");
	printf("\t\t3 - SHA256 hash\n\t\t4 - SHA384 hash\n\t\t5 - SHA512 hash\n");
	printf("\t\t6 - SHA3/224 hash\n\t\t7 - SHA3/256 hash\n");
	printf("\t\t8 - SHA3/384 hash\n\t\t9 - SHA3/512 hash\n");
	printf("\nExample: ./hashsum -h or ./hashsum -t test_string or ./hashsum -f 1.text -a 4\n\n");
}

int
main(int argc, char *argv[])
{
	int res, type = 0, alg = 5;
	char str[4096];
	union context context;
	const struct option long_option [] = {
		{"help",      0, NULL, 'h'},
		{"text",      1, NULL, 't'},
		{"file",      1, NULL, 'f'},
		{"algorithm", 1, NULL, 'a'},
		{0, 	      0, NULL,  0 }
	};

	if(argc < 2) {
		help();
		return 0;
	}

	// Parse argument
	while((res = getopt_long(argc, argv, "t:f:a:h", long_option, 0)) != -1) {
		switch(res) {
		case 't' : strcpy(str, optarg);
			   type = 0;
			   break;
		case 'f' : strcpy(str, optarg);
			   type = 1;
			   break;
		case 'a' : alg = atoi(optarg);
			   break;
		case 'h' : help();
			   return 0;
		}
	}

	// Calculate HASH
	switch(alg) {
	case 0 : printf("MD5 hash:\n");
		 func[type](&(context.md5), alg, str, 0);
		 break;
	case 1 : printf("SHA1 hash:\n");
		 func[type](&(context.sha1), alg, str, 0);
		 break;
	case 2 : printf("SHA224 hash:\n");
		 func[type](&(context.sha224), alg, str, 0);
		 break;
	case 3 : printf("SHA256 hash:\n");
		 func[type](&(context.sha256), alg, str, 0);
		 break;
	case 4 : printf("SHA384 hash:\n");
		 func[type](&(context.sha384), alg, str, 0);
		 break;
	case 5 : printf("SHA512 hash:\n");
		 func[type](&(context.sha512), alg, str, 0);
		 break;
	case 6 : printf("SHA3/224 hash:\n");
		 func[type](&(context.sha3), alg, str, 224);
		 break;
	case 7 : printf("SHA3/256 hash:\n");
		 func[type](&(context.sha3), alg, str, 256);
		 break;
	case 8 : printf("SHA3/384 hash:\n");
		 func[type](&(context.sha3), alg, str, 384);
		 break;
	case 9 : printf("SHA3/512 hash:\n");
		 func[type](&(context.sha3), alg, str, 512);
		 break;
	default:
		 printf("NO such this algorithm!\n");
		 break;
	}

	return 0;
}

