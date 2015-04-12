#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#define BUF_SZ	1024

static void
help(void)
{

}

int
main(int argc, char *argv[])
{
	struct sockaddr_in sockaddr;
	int sd, res, size;
	char buf[BUF_SZ];

	const struct option long_option[] = {
		{"help", 0, NULL, 'h'},
		{"ip",   1, NULL, 'i'},
		{0, 	 0, NULL,  0 }
	};

	while((res = getopt_long(argc, argv, "i:h", long_option, 0)) != -1) {
		switch(res) {
		case 'i' : inet_pton(AF_INET, optarg, &sockaddr.sin_addr);
			   break;
		case 'h' : help();
			   return 0;
		}
	}

	if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("Error! Socket failed!\n");
		exit(1);
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(4444);
	
	int con = 0;

	if((con = connect(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) == -1) {
		printf("Connect error!\n");
		exit(1);
	}

	while(1) {
		if((size = read(0, buf, BUF_SZ)) == -1) {
			printf("Read terminal error!\n");
			exit(1);
		}

		if(write(sd, buf, size) == -1) {
			printf("Write socket error!\n");
			exit(1);
		}

	}

	close(sd);

	return 0;
}

