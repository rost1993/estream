#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#define MAX		4096
#define N		177

// The function search pattern
int
search_pattern(char *str, char *pattern, int n, int i, int j, int flag)
{
	int n1, pos;

	n1 = strlen(pattern);

	for(; i < n; i++) {

		if((int)str[i] == (int)pattern[j]) {
			if((j+1) == n1)
				return i;
			else {
				pos = search_pattern(str, pattern, n, i+1, j+1, 1);
				if(pos == -1) { 
					j = 0;
					continue;
				}
				else
					return pos;
			}
		}
		else {
			if(flag == 1)
				return -1;
		}
	}

	return -1;
}

// Help function
static void
help(void)
{
	printf("\nFind the pattern in the executed file\n");
	printf("Options:\n");
	printf("\t-f(--file) - the executed file\n");
	printf("\t-p(--pattern) - the pattern\n\n");
	printf("\nUsage: ./cryptor -f main -p google\n\n");
}

int
main(int argc, char *argv[])
{
	int fp;
	int res, offset, len, byte, j;
	char file[MAX], str[MAX];
	char pattern[256];

	const struct option long_option [] = {
		{"help",    0, NULL, 'h'},
		{"file",    1, NULL, 'f'},
		{"pattern", 1, NULL, 'p'},
		{0, 	    0, NULL,  0 }
	};

	if(argc < 3) {
		help();
		return 0;
	}

	while((res = getopt_long(argc, argv, "f:p:h", long_option, 0)) != -1) {
		switch(res) {
		case 'h' : help();
			   return 0;
		case 'f' : strcpy(file, optarg);
			   break;
		case 'p' : strcpy(pattern, optarg);
			   break;
		default: help();
			 return 0;
		}
	}

	if((fp = open(file, O_RDWR)) == -1) {
		printf("Error openning the file - %s\n", file);
		exit(1);
	}

	offset = len = j = 0;

	// Search pattern
	while((byte = read(fp, str, MAX)) > 0) {
		
		if((offset = search_pattern(str, pattern, byte, 0, 0, 0)) != -1) {
			if(lseek(fp, offset, SEEK_SET) == -1) {
				printf("Lseek error!\n");
				exit(1);
			}
			
			break;
		}
		
		j += byte;
	}

	if(offset == -1) {
		printf("Matches not found!\n");
		return 0;
	}
	
	printf("\nOffset = %x\n", j + offset);

	j = 0;

	// Search for the second match
	while((byte = read(fp, str, MAX)) > 0) {
		if((len = search_pattern(str, pattern, byte, 0, 0, 0)) != -1)
			break;
		j += byte;
	}

	printf("Length = %x\n\n", j + 1 + len - strlen(pattern));

	close(fp);

	return 0;
}

