#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "estream.h"

#define BUF_SZ	1024

const int ivlen[7] = { 8, 8, 16, 16, 12, 10, 10 };

uint8_t iv[16] = { 0x00, 0x01, 0x02, 0x03,
			 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0A, 0x0B,
			 0x0C, 0x0D, 0x0E, 0x0F };

void (*init[1])(void *) = { (void *)salsa_init };
int (*set[1])(void *, uint8_t *, const int, uint8_t *, const int) = { (void *)salsa_set_key_and_iv };
void (*encrypt[1])(void *, uint8_t *, uint32_t, uint8_t *) = { (void *)salsa_encrypt };

union context {
	struct salsa_context salsa;
};

static void
crypt(void *ctx, char *buf, uint32_t buflen, uint8_t *key, int len, int alg)
{
	(*init[alg])(&ctx);
	
	if((*set[alg])(&ctx, key, len, iv, ivlen[alg])) {
		printf("Salsa context filling error!\n");
		exit(1);
	}
	
	(*encrypt[alg])(&ctx, (uint8_t *)buf, buflen, (uint8_t *)buf);
	
	int i;
	for(i = 0; i < buflen; i++)
		printf("%c", buf[i]);
	printf("Y\n");
}

static void
help(void)
{
	printf("Help!\n");
}

int
main(int argc, char *argv[])
{
	int sd, sdc, res, keylen, alg;
	uint8_t key[32];
	char buf[BUF_SZ];
	int size, i;
	struct sockaddr_in sockaddr;
	union context context;

	const struct option long_option[] = {
		{"help", 0, NULL, 'h'},
		{"ip",   1, NULL, 'i'},
		{ 0, 	 0, NULL,  0 }
	};
	
	if(argc < 2) {
		help();
		return 0;
	}

	while((res = getopt_long(argc, argv, "i:h", long_option, 0)) != -1) {
		switch(res) {
		case 'h' : return 0;
		case 'i' : inet_pton(AF_INET, optarg, &sockaddr.sin_addr);
			   break;
		default: help();
			 return 0;
		}
	}

	if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("Error! Socket failed!\n");
		exit(1);
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(4444);

	if(bind(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
		printf("Bind error!\n");
		close(sd);
		exit(1);
	}

	if(listen(sd, 100)) {
		printf("Listen error!\n");
		close(sd);
		exit(1);
	}

	while(1) {
		pid_t pid;

		if((sdc = accept(sd, NULL, 0)) == -1) {
			printf("Accept error!\n");
			close(sd);
			exit(1);
		}

		pid = fork();

		switch(pid) {
		case -1 : printf("Fork error!\n");
			  exit(1);
		case 0 : if((size = read(sdc, buf, sizeof(buf))) <= 0) {
			 	printf("Read key error!\n");
				close(sd);
				exit(1);
			 }
 
			 // Calculation key and crypto algorithm
			alg = (int)buf[0];
			keylen = size - 1;

			for(i = 1; i <= keylen; i++)
				key[i-1] = (uint8_t)buf[i] ^ 25;
			 
			 while(1) {
				if((size = read(sdc, buf, BUF_SZ)) <= 0) {
					printf("Read error!\n");
					close(sd);
					break;
				}

				crypt(&(context.salsa), buf, size, key, keylen, alg);

				for(i = 0; i < size; i++)
					printf("%c", buf[i]);
			 }
		default: break;
		}

	}
	
	close(sd);
	close(sdc);

	return 0;
}



