#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "estream.h"

#define BUF_SZ	1024

const int keylen[7] = { 32, 16, 16, 32, 16, 10, 10 };
const int ivlen[7]  = {  8,  8, 16, 16, 12, 10, 10 };

const uint8_t iv[16] = { 0x00, 0x01, 0x02, 0x03,
			 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0A, 0x0B,
			 0x0C, 0x0D, 0x0E, 0x0F };

static int
get_keylen(char *s, int alg)
{
	int len;

	len = strlen(s);

	if(len > keylen[alg])
		len = keylen[alg];
	
	return len;
}

static void
help(void)
{
	printf("Help!\n");
}

static void
get_key(char *s, uint8_t *k, int len)
{
	int i;

	for(i = 0; i < len; i++) {
		k[i] = (uint8_t)s[i];
		s[i] ^= 25;
	}
}

static void
crypt(char *buf, uint32_t buflen, uint8_t *key, int len, int alg)
{
	struct salsa_context ctx;

	salsa_init(&ctx);

	if(salsa_set_key_and_iv(&ctx, key, len, iv, ivlen[alg])) {
		printf("Salsa context filling error!\n");
		return ;
	}

	salsa_encrypt(&ctx, (uint8_t *)buf, buflen, (uint8_t *)buf);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in sockaddr;
	int sd, res, size, alg = 0, len;
	char buf[BUF_SZ], k[BUF_SZ];
	uint8_t key[32];

	const struct option long_option[] = {
		{"help", 0, NULL, 'h'},
		{"ip",   1, NULL, 'i'},
		{"key",  1, NULL, 'k'},
		{"type", 1, NULL, 't'},
		{0, 	 0, NULL,  0 }
	};
	
	if(argc < 2) {
		help();
		return 0;
	}

	while((res = getopt_long(argc, argv, "i:k:t:h", long_option, 0)) != -1) {
		switch(res) {
		case 'i' : inet_pton(AF_INET, optarg, &sockaddr.sin_addr);
			   break;
		case 'k' : strcpy(k, optarg);
			   break;
		case 't' : alg = atoi(optarg);
			   break;
		case 'h' : help();
			   return 0;
		default: help();
			 return 0;
		}
	}

	// Calculation key
	len = get_keylen(k, alg);
	get_key(k, key, len);

	if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("Error! Socket failed!\n");
		exit(1);
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(4444);
	
	if(connect(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) {
		printf("Connect error!\n");
		exit(1);
	}

	buf[0] = (char)alg;
	memcpy(buf + 1, k, len);

	if(write(sd, buf, len + 1) == -1) {
		printf("Write key socket error!\n");
		exit(1);
	}

	while(1) {
		if((size = read(0, buf, BUF_SZ)) == -1) {
			printf("Read terminal error!\n");
			exit(1);
		}
		
		crypt(buf, size, key, len, alg);
		
		if(write(sd, buf, size) == -1) {
			printf("Write socket error!\n");
			exit(1);
		}

	}

	close(sd);

	return 0;
}

