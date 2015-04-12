#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>

#define BUF_SIZE	1024

static int
write_all(int fp, void *buf, size_t count)
{
	int writed;

	while(count > 0) {
		writed = write(fp, buf, count);

		if(writed == -1 && errno != EINTR)
			return -1;

		if(writed == 0)
			break;

		count -= writed;
		buf += count;
	}

	return 0;
}

static void
help(void)
{
	printf("\nThe utility encrypts a piece of the executable file!\n");
	printf("Options:\n");
	printf("\t-o - offset from the beginning of the file in hexadecimal format\n");
	printf("\t-k - secret key in hexadecimal format\n");
	printf("\t-l - length piece in hexadecimal format\n");
	printf("\t-h - reference manual\n\n");
	printf("Usage: ./cryptor -k 0xCD -o 0x4CD -l 0x1F [executable file]\n\n");
}

int
main(int argc, char *argv[])
{
	int fp, res, offset, len, i;
	unsigned char key;
	
	len = offset = 0;
	while((res = getopt(argc, argv, "o:k:l:h")) != -1) {
		switch(res) {
		case 'o' : errno = 0;
			   offset = strtol(optarg, NULL, 16);
			   if(errno) {
			   	printf("Argument is not number!\n");
				exit(1);
			   }
			   break;
		case 'k' : key = strtol(optarg, NULL, 16);
			   if(errno) {
			   	printf("Argument is not number!\n");
				exit(1);
			   }
			   break;
		case 'l' : len = strtol(optarg, NULL, 16);
			   if(errno) {
			   	printf("Argument is not number!\n");
				exit(1);
			   }
			   break;
		case 'h' : help();
			   return 0;
		}
	}

	argc -= optind;
	argv += optind;

	if(argc < 1) {
		help();
		return 0;
	}

	if((fp = open(argv[0], O_RDWR | O_CLOEXEC)) == -1) {
		printf("Error openning file!\n");
		exit(1);
	}

	if(lseek(fp, offset, SEEK_SET) == -1) {
		printf("Error lseek!\n");
		exit(1);
	}

	while(len > 0) {
		char buf[BUF_SIZE];
		int n;
		
		n = read(fp, buf, BUF_SIZE);

		if(n == -1) {
			printf("Read error!\n");
			exit(1);
		}
		else if(n == 0) {
			printf("The file is empty!\n");
			exit(1);
		}

		for(i = 0; i < n && i < len; i++)
			buf[i] ^= key;

		if(lseek(fp, -n, SEEK_CUR) == -1) {
			printf("Lseek error!\n");
			exit(1);
		}

		if(write_all(fp, buf, i) != 0) {
			printf("Error the function write_all!\n");
			exit(1);
		}
		
		len -= i;
	}

	printf("\nCryptor completed work!\n\n");

	return 0;
}

