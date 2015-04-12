#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

static void
help(void)
{
	printf("Help!\n");
}

int
main(int argc, char *argv[])
{
	int sd, sdc, res;
	char buf[256];
	int size, i;
	struct sockaddr_in sockaddr;

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
		case 0 :  while(1) {
				if((size = read(sdc, buf, sizeof(buf))) <= 0) {
					printf("Read error!\n");
					close(sd);
					break;;
				}

			  for(i = 0; i < size; i++)
				printf("%c", buf[i]);
			  printf("\n");

			 }
		default: break;
		}

	}
	
	close(sd);
	close(sdc);

	return 0;
}

