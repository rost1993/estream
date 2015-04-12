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

// Global variable
uint32_t block = 1000000;
uint8_t key[32];
uint8_t iv[16];
int keylen;
int ivlen;

// Interface to the library salsa.h
static int
salsa(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
	struct salsa_context ctx;
	uint32_t byte;

	salsa_init(&ctx);

	if(salsa_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
		return -1;

	while((byte = fread(buf, 1, block, fp)) > 0) {
		salsa_encrypt(&ctx, buf, byte, out);
			
		fwrite(out, 1, byte, fd);
	}

	return 0;
}

// Interface to the library rabbit.h
static int
rabbit(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
	struct rabbit_context ctx;
	uint32_t byte;
 
	rabbit_init(&ctx);

	if(rabbit_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
		return -1;
  
	while((byte = fread(buf, 1, block, fp)) > 0) {
		rabbit_encrypt(&ctx, buf, byte, out);
		
		fwrite(out, 1, byte, fd);
	}
         
	return 0;
}

// Interface to the library sosemanuk.h
static int
sosemanuk(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
	struct sosemanuk_context ctx;
	uint32_t byte;

	sosemanuk_init(&ctx);

	if(sosemanuk_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
		return -1;
	
	while((byte = fread(buf, 1, block, fp)) > 0) {
		sosemanuk_encrypt(&ctx, buf, byte, out);

		fwrite(out, 1, byte, fd);
	}

	return 0;
}

// Interface to the library hc128.h
static int
hc128(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
	struct hc128_context ctx;
	uint32_t byte;

	hc128_init(&ctx);
 
	if(hc128_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
		return -1;
	
	while((byte = fread(buf, 1, block, fp)) > 0) {
		hc128_encrypt(&ctx, buf, byte, out);

		fwrite(out, 1, byte, fd);
	}
  
	return 0;
}

// Interface to the library grain.h
static int
grain(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
	struct grain_context ctx;
	uint32_t byte;

	grain_init(&ctx);
 
	if(grain_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
		return -1;

	while((byte = fread(buf, 1, block, fp)) > 0) {
		grain_encrypt(&ctx, buf, byte, out);

		fwrite(out, 1, byte, fd);
	}
  
	return 0;
}

// Interface to the library mickey.h
static int
mickey(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
	struct mickey_context ctx;
	uint32_t byte;

	mickey_init(&ctx);
 
	if(mickey_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
		return -1;
  
	while((byte = fread(buf, 1, block, fp)) > 0) {
		mickey_encrypt(&ctx, buf, byte, out);
       
		fwrite(out, 1, byte, fd);
	}
  
	return 0;
}

// Interface to the library trivium.h
static int
trivium(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
	struct trivium_context ctx;
	uint32_t byte;

	trivium_init(&ctx);

	if(trivium_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
		return -1;
  
	while((byte = fread(buf, 1, block, fp)) > 0) {
		trivium_encrypt(&ctx, buf, byte, out);
     
		fwrite(out, 1, byte, fd);
	}
  
	return 0;
}

// Copy key and IV
void
get_key_and_iv(char *k, char *v)
{
	memcpy(key, k, keylen);
	memcpy(iv, v, ivlen);
}

// Manual of the program
void
help(void)
{
	printf("\nThis program allows you to encrypt and decrypt files using algorithms project eSTREAM!\n");
	printf("\nOptions:\n");
	printf("\t--help(-h) - reference manual\n");
	printf("\t--algorothm(-a) - selection algorithm:\n");
	printf("\t\t1 - Salsa\n\t\t2 - Rabbit\n\t\t3 - HC128\n\t\t4 - Sosemanuk\n");
	printf("\t\t5 - Grain\n\t\t6 - Mickey\n\t\t7 - Trivium\n");
	printf("\t--input(-i) - input file\n");
	printf("\t--output(-o) - output file\n");
	printf("\nExample: ./estream -h or ./estream -a 1 -i 1.tx -o 2.txt\n\n");
}

// Base function
int
main(int argc, char *argv[])
{
	FILE *fp, *fd;
	char in_file[MAX_FILE], out_file[MAX_FILE], k[256], v[256];
	uint8_t *buf, *out;
	int res, alg = 1;

	// Array pointer to the function encrypt/decrypt
	int (*p[7])(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out) = { salsa, rabbit, hc128, sosemanuk, grain, mickey, trivium };

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
	
	// Allocates memory for the buffer data
	if((buf = malloc(sizeof(uint8_t) * block)) == NULL) {
		printf("Error allocates memory for the buffer data!\n");
		return 0;
	}

	// Allocates memory for the output buffer data
	if((out = malloc(sizeof(uint8_t) * block)) == NULL) {
		printf("Error allocates memory for the out buffer data!\n");
		return 0;
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
	case 1 : if(keylen > 32)
		 	keylen = 32;
		 
		 if(ivlen > 8)
		 	ivlen = 8;

		 get_key_and_iv(k, v);

		 if((*p[0])(fp, fd, buf, out)) {
		 	printf("Salsa function failed with error!\n");
			return 0;
		   }
		 break;
	case 2 : if(keylen > 16)
		   	keylen = 16;
		 
		 if(ivlen > 8)
		 	ivlen = 8;

		 get_key_and_iv(k, v);

		 if((*p[1])(fp, fd, buf, out)) {
		 	printf("Rabbit function failed with error!\n");
			return 0;
		 }
		 break;
	case 3 : if(keylen > 16)
		   	keylen = 16;

		 if(ivlen > 16)
		 	ivlen = 16;

		 get_key_and_iv(k, v);

		 if((*p[2])(fp, fd, buf, out)) {
		   	printf("HC128 function failed with error!\n");
			return 0;
		 }
		 break;
	case 4 : if(keylen > 32)
		   	keylen = 32;

		 if(ivlen > 16)
		 	ivlen = 16;

		 get_key_and_iv(k, v);

		 if((*p[3])(fp, fd, buf, out)) {
		   	printf("Sosemanuk function failed with error!\n");
			return 0;
		 }
		 break;
	case 5 : if(keylen > 16)
		   	keylen = 16;

		 if(ivlen > 12)
		 	ivlen = 12;

		 get_key_and_iv(k, v);

		 if((*p[4])(fp, fd, buf, out)) {
		   	printf("Grain function failed with error!\n");
			return 0;
		 }
		 break;
	case 6 : if(keylen > 10)
		   	keylen = 10;

		 if(ivlen > 10)
		 	keylen = 10;

		 get_key_and_iv(k, v);

		 if((*p[5])(fp, fd, buf, out)) {
		   	printf("Mickey function failed with error!\n");
			return 0;
		 }
		 break;
	case 7 : if(keylen > 10)
		   	keylen = 10;
		 
		 if(ivlen > 10)
		 	ivlen = 10;

		 get_key_and_iv(k, v);

		 if((*p[6])(fp, fd, buf, out)) {
		   	printf("Trivium function failed with error!\n");
			return 0;
		 }
		 break;
	default: printf("\nNo such algorithm!\n");
		 break;
	}

	fclose(fp);
	fclose(fd);
	
	free(buf);
	free(out);

	return 0;
}

