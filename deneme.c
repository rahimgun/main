#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define STR_LEN 100
#define BUF_LEN 1024

int main(int argc, char **argv)
{
	/*
	if (argc != 3) {
		fprintf(stderr, "Usage : %s hostname port\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	*/
	int sockfd = 0, valread = 0;

	char command[BUF_LEN] = {0};
	char quit[5] = "quit";
	char enable[7] = "enable";
	char cli_print[10] = "cli_print";
	char *token = NULL;
	char pid_to_send[1024] = {0};
	char recvBuff[BUF_LEN];
	char sendBuff[BUF_LEN];

	pid_t pid;
	struct sockaddr_in serv_addr;

	memset(recvBuff, '0', sizeof(recvBuff));
	memset(sendBuff, '0', sizeof(sendBuff));

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("failed to create socket in cli: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));
	memset(&(serv_addr.sin_zero), '\0', 8);

	if ((connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) == -1){
		printf("connect failed in cli: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	

	pid = getpid();
	sprintf(pid_to_send, "%d", pid);
	
	int asd;
	asd = send(sockfd, pid_to_send, BUF_LEN, 0);
	if (asd == -1) {
		printf("failed to send: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	char* asdzxc[3];
	asdzxc[0] = (char *) malloc(STR_LEN);
	asdzxc[1] = (char *) malloc(STR_LEN);
	asdzxc[2] = (char *) malloc(STR_LEN);
	strcpy(asdzxc[0], "3");
	strcpy(asdzxc[1], "cli_get");
	strcpy(asdzxc[2], "Device.Time.NTPServer1");
	asd = send(sockfd, asdzxc[0], BUF_LEN, 0);
	if (asd == -1) {
		printf("failed to send: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	asd = send(sockfd, asdzxc[1], BUF_LEN, 0);
	if (asd == -1) {
		printf("failed to send: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	asd = send(sockfd, asdzxc[2], BUF_LEN, 0);
	if (asd == -1) {
		printf("failed to send: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	valread = read(sockfd, recvBuff, BUF_LEN);
	if (valread == -1) {
		printf("failed to read: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	printf("%.*s", valread, recvBuff);

	int test;
	test = send(sockfd, pid_to_send, 1024, 0);
	if (test == -1) {
		printf("failed to send: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	char* quit1[2];
	quit1[0] = (char *) malloc(STR_LEN);
	quit1[1] = (char *) malloc(STR_LEN);
	strcpy(quit1[0], "2");
	strcpy(quit1[1], "quit");
	test = send(sockfd, quit1[0], BUF_LEN, 0);
	if (test == -1) {
		printf("failed to send: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	test = send(sockfd, quit1[1], BUF_LEN, 0);
	if (test == -1) {
		printf("failed to send: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (close(sockfd) == -1) {
		printf("error: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return 0;
}