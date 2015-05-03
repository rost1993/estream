/*
 * This program provides an interface for testing algorithms eSTREAM pojects.
 * Makefile: Makefile
 * Compile: make
 * Example: ./estream -h or ./estream -a 1 -i 1.txt -o 2.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <getopt.h>

#include "estream.h"

#define MAX_FILE 	4096
#define BLOCK		1000000

// Global variable
uint8_t key[32];
uint8_t iv[16];
int keylen;
int ivlen;

// Union all structures eSTREAM project
union context {
	struct salsa_context salsa;
	struct rabbit_context rabbit;
	struct hc128_context hc128;
	struct sosemanuk_context sosemanuk;
	struct grain_context grain;
	struct mickey_context mickey;
	struct trivium_context trivium;
};

typedef int (*set_t)(void *ctx, uint8_t *key, int keylen, uint8_t *iv, int ivlen);
typedef void (*crypt_t)(void *ctx, uint8_t *buf, uint32_t buflen, uint8_t *out);

// Pointer of the function eSTREAM project
set_t set[] = { (set_t)salsa_set_key_and_iv,
		(set_t)rabbit_set_key_and_iv,
		(set_t)hc128_set_key_and_iv,
		(set_t)sosemanuk_set_key_and_iv,
		(set_t)grain_set_key_and_iv,
		(set_t)mickey_set_key_and_iv,
		(set_t)trivium_set_key_and_iv };

crypt_t crypt[] = { (crypt_t)salsa_crypt,
		    (crypt_t)rabbit_crypt,
		    (crypt_t)hc128_crypt,
		    (crypt_t)sosemanuk_crypt,
		    (crypt_t)grain_crypt,
		    (crypt_t)mickey_crypt,
		    (crypt_t)trivium_crypt };

// Copy key and IV
void
get_key_and_iv(char *k, char *v)
{
	memcpy(key, k, keylen);
	memcpy(iv, v, ivlen);
}

// Crypting function
int
crypt_func(FILE *fp, FILE *fd, void *ctx, int alg)
{
	uint8_t buf[BLOCK], out[BLOCK];
	uint32_t byte;

	if(set[alg](ctx, key, keylen, iv, ivlen))
		return -1;

	while((byte = fread(buf, 1, BLOCK, fp)) > 0) {
		crypt[alg](ctx, buf, byte, out);
		fwrite(out, 1, byte, fd);
	}

	return 0;
}

// Manual of the program
void
help(void)
{
	printf("\nThis program allows you to encrypt and decrypt files using algorithms project eSTREAM!\n");
	printf("\nOptions:\n");
	printf("\t--help(-h) - reference manual\n");
	printf("\t--algorothm(-a) - selection algorithm:\n");
	printf("\t\t0 - Salsa\n\t\t1 - Rabbit\n\t\t2 - HC128\n\t\t3 - Sosemanuk\n");
	printf("\t\t4 - Grain\n\t\t5 - Mickey\n\t\t6 - Trivium\n");
	printf("\t--input(-i) - input file\n");
	printf("\t--output(-o) - output file\n");
	printf("\nExample: ./estream -h or ./estream -a 1 -i 1.tx -o 2.txt\n\n");
}

// Base function
int
main(int argc, char *argv[])
{
	FILE *fp, *fd;
	union context context;
	char in_file[MAX_FILE], out_file[MAX_FILE], k[256], v[256];
	int res, alg = 1;

	const struct option long_option [] = {
		{"help",      0, NULL, 'h'},
		{"input",     1, NULL, 'i'},
		{"output",    1, NULL, 'o'},
		{"algorithm", 1, NULL, 'a'},
		{0,        0, NULL,  0 }
	};

	if(argc < 2) {
		help();
		return 0;
	}

	// Parse arguments
	while((res = getopt_long(argc, argv, "a:i:o:h", long_option, 0)) != -1) {
		switch(res) {
		case 'h' : help();
			   return 0;
		case 'i' : strcpy(in_file, optarg);
			   break;
		case 'o' : strcpy(out_file, optarg);
			   break;
		case 'a' : alg = atoi(optarg);
			   break;
		}
	}
	
	// Open the input file
	if((fp = fopen(in_file, "rb+")) == NULL) {
		printf("Error open the file - %s!\n", in_file);
		return 0;
	}

	// Open the output file
	if((fd = fopen(out_file, "wb+")) == NULL) {
		printf("Error open the file - %s!\n", out_file);
		return 0;
	}

	// Enter the secret key
	printf("Enter secret key - ");
	scanf("%s", k);
	keylen = strlen(k);
	
	// Enter the vector initialization
	printf("Enter vector initialization - ");
	scanf("%s", v);
	ivlen = strlen(v);

	// Select algorithm
	switch(alg) {
	case 0 : if(keylen > 32)
		 	keylen = 32;
		 
		 if(ivlen > 8)
		 	ivlen = 8;

		 get_key_and_iv(k, v);

		 res = crypt_func(fp, fd, &(context.salsa), alg);
		 break;
	case 1 : if(keylen > 16)
		   	keylen = 16;
		 
		 if(ivlen > 8)
		 	ivlen = 8;

		 get_key_and_iv(k, v);

		 res = crypt_func(fp, fd, &(context.rabbit), alg);
		 break;
	case 2 : if(keylen > 16)
		   	keylen = 16;

		 if(ivlen > 16)
		 	ivlen = 16;

		 get_key_and_iv(k, v);

		 res = crypt_func(fp, fd, &(context.hc128), alg);
		 break;
	case 3 : if(keylen > 32)
		   	keylen = 32;

		 if(ivlen > 16)
		 	ivlen = 16;

		 get_key_and_iv(k, v);

		 res = crypt_func(fp, fd, &(context.sosemanuk), alg);
		 break;
	case 4 : if(keylen > 16)
		   	keylen = 16;

		 if(ivlen > 12)
		 	ivlen = 12;

		 get_key_and_iv(k, v);

		 res = crypt_func(fp, fd, &(context.grain), alg);
		 break;
	case 5 : if(keylen > 10)
		   	keylen = 10;

		 if(ivlen > 10)
		 	keylen = 10;

		 get_key_and_iv(k, v);

		 res = crypt_func(fp, fd, &(context.mickey), alg);
		 break;
	case 6 : if(keylen > 10)
		   	keylen = 10;
		 
		 if(ivlen > 10)
		 	ivlen = 10;

		 get_key_and_iv(k, v);

		 res = crypt_func(fp, fd, &(context.trivium), alg);
		 break;
	default: printf("\nNo such algorithm!\n");
		 break;
	}

	fclose(fp);
	fclose(fd);

	if (res == -1)
		printf("Error in crypting! Exit...\n");
	else
		printf("Completed succesfully! Exit...\n");

	return 0;
}

