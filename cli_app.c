/**
 * @file cli_app.c
 * @brief 
 * @version 0.1
 * @date 2021-08-25
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dmalloc.h>

#define STR_LEN 100
#define BUF_LEN 1024

/**
 * @struct params 
 * 
 * First node contains size of command, second node contains
 * name of method and other holds options of methods 
 * 
 */
struct params{
	char param[STR_LEN];
	struct params *next;
};

void insert(char *param, struct params **head);
void init(char *param, struct params **head);
void free_list(struct params **head);
int list_len(struct params **head);
void handle_write(int signum);
void insert_module();
void remove_module();
void read_kernel_buffer();

volatile sig_atomic_t gWrite_done = 0;

/**
 * @brief get commands from user and redirect them to main app
 * 
 * It creates a IP address with given host name and port number. 
 * Then it creates a socket and connect it. It reads commands from user
 * until quit is written. For each command, it tokenizes command with
 * space. It inserts each token to linked list and send them to main app.
 * Then it reads from until signal is received. Finally it frees linked list
 * and reset gWrite_done
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char **argv)
{
	
	if (!(argc > 2 && argc < 5)) {
		fprintf(stderr, "Usage : %s hostname port\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	int sockfd = 0, valread = 0;
	int s, rc;

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
	struct sockaddr_un serv_addr_un;
	struct sockaddr_storage addr;
	struct in6_addr serv;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	struct sigaction sa;

	sa.sa_handler = handle_write; 
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGUSR1, &sa, NULL) == 1) {
		printf("error %d | %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if (!strcmp(argv[1], "inet")) {
		memset(recvBuff, '0', sizeof(recvBuff));
		memset(sendBuff, '0', sizeof(sendBuff));

		s = getaddrinfo(argv[2], argv[3], &hints, &result);
		if (s != 0) {
			printf("getaddrinfo failed %s\n", gai_strerror(s));
			exit(EXIT_FAILURE);
		}

		for (rp = result; rp != NULL; rp = rp->ai_next) {
			sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

			if (sockfd == -1) {
				continue;
			}
			
			rc = connect(sockfd, rp->ai_addr, rp->ai_addrlen);

			if (rc == -1) {
				printf("failed to connect: %d | %s \n", errno, strerror(errno));
				close(sockfd);
				exit(EXIT_FAILURE);
			} else {
				break;
			}

			
		}

		freeaddrinfo(result);

		if (rp == NULL) {
			printf("Could not connect\n");
			exit(EXIT_FAILURE);
		}
		/*
		memset(&serv_addr, 0, sizeof(serv_addr));

		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			printf("failed to create ip socket in cli: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = inet_addr(argv[2]);
		serv_addr.sin_port = htons(atoi(argv[3]));
		memset(&(serv_addr.sin_zero), '\0', 8);

		if ((connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) == -1){
			printf("connect failed in cli: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		*/
	} 
	else if (!strcmp(argv[1], "unix")) {
		memset(&serv_addr_un, 0, sizeof(serv_addr_un));
		memset(recvBuff, '0', sizeof(recvBuff));
		memset(sendBuff, '0', sizeof(sendBuff));

		if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
			printf("failed to create unix socket in cli: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		serv_addr_un.sun_family = AF_UNIX;
		strcpy(serv_addr_un.sun_path, argv[2]);

		if ((connect(sockfd, (struct sockaddr *) &serv_addr_un, sizeof(serv_addr_un))) == -1){
			printf("connect failed in cli: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	dmalloc_debug_setup("log-stats,log-non-free, check-fense, check-heap, error-abort,log=cli_logfile.log");

	pid = getpid();
	sprintf(pid_to_send, "%d", pid);
	
	printf("Write quit to terminate\n");
	printf("#>");

	//str = fgets(command,1000,stdin);

	while (fgets(command,BUF_LEN,stdin)) {
		
		gWrite_done = 0; /* reset gWrite_done*/
		if (!strncmp(command,quit,4)) { /* end program when user enters quit*/
			int test;
			test = send(sockfd, pid_to_send, 1024, 0);
			if (test == -1) {
				printf("failed to send: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			char* quit[2];
			quit[0] = (char *) malloc(STR_LEN);
			quit[1] = (char *) malloc(STR_LEN);
			strcpy(quit[0], "2");
			strcpy(quit[1], "quit");
			test = send(sockfd, quit[0], BUF_LEN, 0);
			if (test == -1) {
				printf("failed to send: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			test = send(sockfd, quit[1], BUF_LEN, 0);
			if (test == -1) {
				printf("failed to send: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			free(quit[0]);
			free(quit[1]);
			break;
		}
		send(sockfd, pid_to_send, 1024, 0);
		struct params *head;
		init("./main", &head);
		/* it splits command by space and insert to linked list*/
		token = strtok(command, " ");
		while ( token != NULL ) {
			insert(token,&head);
			token = strtok(NULL, " ");
		}
		struct params *current = head;
		int len = list_len(&head);
		char* args[len];
		int i = 0;

		while (current != NULL) {
			args[i] = (char *) malloc(STR_LEN);
			strcpy(args[i], current->param);
			current = current->next;
			i++;
		}
		sprintf(args[0], "%d", len);/*change first node to size of linked list*/

		/* remove new line character from last part of command*/
		int last = strlen(args[len-1]);
		if (args[len-1][last-1] == '\n') {
			args[len-1][last-1] = '\0';
		}
		/* call insert or remove module function when user enters enable*/
		int k = 0;
		if (strncmp(enable, args[1], 7) == 0) {
			if (atoi(args[2]) == 1) {
				insert_module();
			}
			else if (atoi(args[2]) == 0) {
				remove_module();
			}
			printf("#>>");
			for (k = 0 ; k < len ; k++) {
				free(args[k]);
			}
			free_list(&head);
			continue;
		}
		/* prints random number from kernel buffer when user enters cli_print*/
		if (strncmp(cli_print, args[1], 9) == 0) {
			read_kernel_buffer();
			printf("#>>");
			for (k = 0 ; k < len ; k++) {
				free(args[k]);
			}
			free_list(&head);
			continue;
		}
		
		for (k = 0 ; k < len ; k++) {
			//printf("%s = %d \n", args[k], strlen(args[k]));
			send(sockfd, args[k], BUF_LEN, 0);
		}
		
		while (!gWrite_done) {
			valread = read(sockfd, recvBuff, BUF_LEN);
			if (valread == -1) {
				if (errno == EINTR) {/* break loop when read is interrupted*/
					break;
				}
			}
			printf("%.*s", valread, recvBuff);
			fflush(stdout);
		}
		/* free linked list and args before getting new command*/
		if (gWrite_done == 1) {
			printf("#>>");
			for (k = 0 ; k < len ; k++) {
				free(args[k]);
			}
			free_list(&head);
			continue;
		}
		

		for (k = 0 ; k < len ; k++) {
			free(args[k]);
		}
		free_list(&head);
		printf("#>");
		//str = fgets(command,1000,stdin);
	}
	///sleep(1);
	
	if (close(sockfd) == -1) {
		printf("error: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	dmalloc_shutdown();
	return 0;
}
/**
 * @brief init linked list.
 * 
 * It initializes a linked list for command
 * 
 * @param param
 * @param head
 */
void init(char *param, struct params **head)
{
	*head = (struct params*) malloc(sizeof(struct params));

	strcpy((*head)->param, param);
	(*head)->next = NULL;

}
/**
 * @brief insert new node to linked list.
 * 
 * It goes to end of linked list. Then allocate memory for new node
 * and copy parameter to the node. It adds new node to end of linked list.
 * 
 * @param param 
 * @param head 
 */
void insert(char *param, struct params **head)
{
	struct params *current = *head;

	while (current->next != NULL) {
		current = current->next;
	}
	
	struct params *new_node = (struct params*) malloc(sizeof(struct params));
	new_node->next = NULL;
	strcpy(new_node->param, param);

	current->next = new_node;

}
/**
 * @brief free linked list after command is executed.
 * 
 * It traverses linked list and free each node.
 * 
 * @param head 
 */
void free_list(struct params **head)
{
	struct params *current = *head;
	do {
		struct params *tmp;
		tmp = current;
		current = current->next;
		free(tmp);
	} while(current);
}
/**
 * @brief find the length of linked list.
 * 
 * It traverses linked list and increments count
 * for each node. 
 * 
 * @param head 
 * @return int size of linked list
 * 
 */
int list_len(struct params **head)
{
	struct params *current = *head;
	int count = 0;
	while (current != NULL) {
		count++;
		current = current->next;
	}

	return count;

}
/**
 * @brief indicates write is done.
 * 
 * It assign 1 to gWrite_done to stop read function.
 * Read function is interrupted to get new command from user.
 * 
 * @param signum 
 */
void handle_write(int signum)
{
	gWrite_done = 1;
}

/**
 * @brief load kernel module
 * 
 * calls insmod command with ready kernel module
 * Root privileges are required to run this function.
 */
void insert_module()
{
	char *command[] = {"insmod", "./lkm_example.ko", NULL};
	pid_t pid;

	pid = fork();

	if (pid == -1) {
		printf("error: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		execvp(command[0], command);
	} else {
		printf("module loaded\n");
	}
}

/**
 * @brief unload kernel module
 * 
 * it removes kernel module with rmmod
 * Root privileges are required to run this function.
 */
void remove_module() 
{
	char *command[] = {"rmmod", "lkm_example.ko", NULL};
	pid_t pid;

	pid = fork();

	if (pid == -1) {
		printf("error: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		execvp(command[0], command);
	} else {
		printf("module removed\n");
	}
}
/**
 * @brief print kernel buffer
 * 
 * it searches dmesg output and find
 * last occurence of random number generated by kernel module
 * 
 */
void read_kernel_buffer()
{
	system("dmesg -t | grep \"lkm_example_rand_number\" | tail -1");
}
