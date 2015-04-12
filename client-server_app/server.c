#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

int
main(int argc, char *argv[])
{
	int sd, sdc;
	char buf[256];
	int size, i;

	struct sockaddr_in sockaddr;

	if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("Error! Socket failed!\n");
		exit(1);
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(4444);
	inet_pton(AF_INET, "192.168.0.4", &sockaddr.sin_addr);

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

	if((sdc = accept(sd, NULL, 0)) == -1) {
		printf("Accept error!\n");
		close(sd);
		exit(1);
	}

	while(1) {
		if((size = read(sdc, buf, sizeof(buf))) == -1) {
			printf("Read error!\n");
			close(sd);
			exit(1);
		}

		for(i = 0; i < size; i++)
			printf("%c", buf[i]);
		printf("\n");

	}

	close(sd);
	close(sdc);

	return 0;
}

