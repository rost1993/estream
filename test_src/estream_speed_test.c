#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/time.h>

#include "estream.h"

#define BUFLEN		100000000

struct timeval t1, t2;

uint8_t buf[BUFLEN];
uint8_t out1[BUFLEN];
uint8_t out2[BUFLEN];

uint8_t key[32] = { 0x00, 0x11, 0x22, 0x33,
		    0x44, 0x55, 0x66, 0x77,
		    0x88, 0x99, 0xAA, 0xBB,
		    0xCC, 0xDD, 0xEE, 0xFF,
		    0x00, 0x11, 0x22, 0x33,
		    0x44, 0x55, 0x66, 0x77,
		    0x88, 0x99, 0xAA, 0xBB,
		    0xCC, 0xDD, 0xEE, 0xFF };

uint8_t iv[16] = { 0x01, 0x23, 0x45, 0x67,
		   0x89, 0xAB, 0xCD, 0xEF,
		   0x01, 0x23, 0x45, 0x67,
		   0x89, 0xAB, 0xCD, 0xEF };

static void
time_start(void)
{
	gettimeofday(&t1, NULL);
}

static uint32_t
time_stop(void)
{
	gettimeofday(&t2, NULL);

	t2.tv_sec -= t1.tv_sec;
	t2.tv_usec -= t1.tv_usec;

	if(t2.tv_usec < 0) {
		t2.tv_sec--;
		t2.tv_usec += 1000000;
	}
	
	return (t2.tv_sec * 1000 + t2.tv_usec/1000);
}

static void
salsa(void)
{
	struct salsa_context ctx;
	
	time_start();

	salsa_init(&ctx);

	if(salsa_set_key_and_iv(&ctx, key, 32, iv, 8)) {
		printf("Salsa context filling error!\n");
		exit(1);
	}
	
	salsa_encrypt(&ctx, buf, BUFLEN, out1);

	salsa_init(&ctx);

	if(salsa_set_key_and_iv(&ctx, key, 32, iv, 8)) {
		printf("Salsa context filling error!\n");
		exit(1);
	}
	
	salsa_decrypt(&ctx, out1, BUFLEN, out2);

	printf("\nRun time Salsa of the %d bytes - %d\n\n", BUFLEN, time_stop());
}

static void
rabbit(void)
{
	struct rabbit_context ctx;

	time_start();

	rabbit_init(&ctx);

	if(rabbit_set_key_and_iv(&ctx, key, 16, iv, 8)) {
		printf("Rabbit context filling error!\n");
		exit(1);
	}
	
	rabbit_encrypt(&ctx, buf, BUFLEN, out1);

	rabbit_init(&ctx);

	if(rabbit_set_key_and_iv(&ctx, key, 16, iv, 8)) {
		printf("Rabbit context filling error!\n");
		exit(1);
	}

	rabbit_decrypt(&ctx, out1, BUFLEN, out2);

	printf("\nRun time Rabbit of the %d bytes - %d\n\n", BUFLEN, time_stop());
}

static void
hc128(void)
{
	struct hc128_context ctx;
         
	time_start();

	hc128_init(&ctx);
	
	if(hc128_set_key_and_iv(&ctx, key, 16, iv, 16)) {
		printf("HC128 context filling error!\n");
		exit(1);
	}

	hc128_encrypt(&ctx, buf, BUFLEN, out1);
        
	hc128_init(&ctx);

	if(hc128_set_key_and_iv(&ctx, key, 16, iv, 16)) {
		printf("HC128 context filling error!\n");
		exit(1);
	}
         
	hc128_decrypt(&ctx, out1, BUFLEN, out2);
       
	printf("\nRun time HC128 of the %d bytes - %d\n\n", BUFLEN, time_stop());
}

static void
sosemanuk(void)
{
	struct sosemanuk_context ctx;
	
	time_start();

	sosemanuk_init(&ctx);

	if(sosemanuk_set_key_and_iv(&ctx, key, 32, iv, 16)) {
		printf("Sosemanuk context filling error!\n");
		exit(1);
	}

	sosemanuk_encrypt(&ctx, buf, BUFLEN, out1);
         
	sosemanuk_init(&ctx);

	if(sosemanuk_set_key_and_iv(&ctx, key, 32, iv, 16)) {
		printf("Sosemanuk context filling error!\n");
		exit(1);
	}
         
	sosemanuk_decrypt(&ctx, out1, BUFLEN, out2);
        
	printf("\nRun time Sosemanuk of the %d bytes - %d\n\n", BUFLEN, time_stop());
}

static void
grain(void)
{
	struct grain_context ctx;

	time_start();

	grain_init(&ctx);

	if(grain_set_key_and_iv(&ctx, key, 16, iv, 12)) {
		printf("Grain context filling error!\n");
		exit(1);
	}

	grain_encrypt(&ctx, buf, BUFLEN, out1);

	grain_init(&ctx);
        
	if(grain_set_key_and_iv(&ctx, key, 16, iv, 12)) {
		printf("Grain context filling error!\n");
		exit(1);
	}
        
	grain_decrypt(&ctx, out1, BUFLEN, out2);
        
	printf("\nRun time Grain of the %d bytes - %d\n\n", BUFLEN, time_stop());
}

static void
mickey(void)
{
	struct mickey_context ctx;
       
	time_start();

	mickey_init(&ctx);

	if(mickey_set_key_and_iv(&ctx, key, 10, iv, 10)) {
		printf("Mickey context filling error!\n");
		exit(1);
	}
 
	mickey_encrypt(&ctx, buf, BUFLEN, out1);

	mickey_init(&ctx);
	
	if(mickey_set_key_and_iv(&ctx, key, 10, iv, 10)) {
		printf("Mickey context filling error!\n");
		exit(1);
	}
	        
	mickey_decrypt(&ctx, out1, BUFLEN, out2);
        
	printf("\nRun time Mickey of the %d bytes - %d\n\n", BUFLEN, time_stop());
}

static void
trivium(void)
{
	struct trivium_context ctx;
    
	time_start();

	trivium_init(&ctx);

	if(trivium_set_key_and_iv(&ctx, key, 10, iv, 10)) {
		printf("Trivium context filling error!\n");
		exit(1);
	}
	
	trivium_encrypt(&ctx, buf, BUFLEN, out1);
	
	trivium_init(&ctx);

	if(trivium_set_key_and_iv(&ctx, key, 10, iv, 10)) {
		printf("Trivium context filling error!\n");
		exit(1);
	}
	        
	trivium_decrypt(&ctx, out1, BUFLEN, out2);
	       
	printf("\nRun time Trivium of the %d bytes - %d\n\n", BUFLEN, time_stop());
}

static void
help(void)
{
	printf("\nThis program provides the user interface for testing algorithms project eSTREAM on speed test!\n");
	printf("\nOptions:\n");
	printf("\t--help(-h) - reference manual\n");
	printf("\t--algorithm(-a) - selection algorithm:\n");
	printf("\t\t1 - Salsa\n\t\t2 - Rabbit\n\t\t3 - HC128\n\t\t4 - Sosemanuk\n");
	printf("\t\t5 - Grain\n\t\t6 - Mickey\n\t\t7 - Trivium\n");
	printf("\nExample: ./estream_testvectors -h or ./estream_testvectors -a 1\n\n");
}

int
main(int argc, char *argv[])
{
	int res, alg = 0;

	const struct option long_option [] = {
		{"algorithm", 1, NULL, 'a'},
		{"help",      0, NULL, 'h'},
		{0, 	      0, NULL,  0 }
	};
	
	if(argc < 2) {
		help();
		return 0;
	}
	
	while((res = getopt_long(argc, argv, "a:h", long_option, 0)) != -1) {
		switch(res) {
		case 'h' : help();
			   return 0;
		case 'a' : alg = atoi(optarg);
			   break;
		}
	}

	switch(alg) {
	case 1 : salsa();
		 break;
	case 2 : rabbit();
		 break;
	case 3 : hc128();
		 break;
	case 4 : sosemanuk();
		 break;
	case 5 : grain();
		 break;
	case 6 : mickey();
		 break;
	case 7 : trivium();
		 break;
	}
	
	return 0;
}

