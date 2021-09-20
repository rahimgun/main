/**
 * @file cli_app.c
 * @brief 
 * @version 0.1
 * @date 2021-08-25
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <string.h>
#include <ifaddrs.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dmalloc.h>

#define STR_LEN 100 /**< size of command or option*/
#define BUF_LEN 1024 /**< send and recv buffer length*/

/**
 * @struct params 
 * 
 * First node contains size of command, second node contains
 * name of method and other holds options of methods 
 * 
 */
struct params{
	char param[STR_LEN]; /**< method name or options*/
	struct params *next; /**< next item in the list */
};

int inet(char* host, char* port);
int unix_d(char* file);
int interface(char* interface, char* port);
void insert(char *param, struct params **head);
void init(char *param, struct params **head);
void free_list(struct params **head);
int list_len(struct params **head);
void handle_write();
void insert_module();
void remove_module();
void read_kernel_buffer();

volatile sig_atomic_t gWrite_done = 0; /**< indicates main app send writing is done*/

/**
 * @brief get commands from user and redirect them to main app.
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
	/*	
	if (!(argc > 2 && argc < 5)) {
		fprintf(stderr, "Usage : %s hostname port\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	*/
	int sockfd = 0, valread = 0;
	int dflag = 0, pflag = 0, hflag = 0, fflag = 0, iflag = 0;
	char *dvalue = NULL, *pvalue = NULL, *hvalue = NULL, *fvalue = NULL, *ivalue = NULL;
	int c;
	int option_index = 0;

	char command[BUF_LEN] = {0};
	const char *quit = NULL;
	const char *enable = NULL;
	const char *cli_print = NULL;
	char *token = NULL;
	char pid_to_send[BUF_LEN] = {0};
	char recvBuff[BUF_LEN];
	char sendBuff[BUF_LEN];

	pid_t pid;
	struct sigaction sa;

	quit = "quit";
	enable = "enable";
	cli_print = "cli_print";

	static struct option long_options[] =
	{
		{"domain", required_argument, 0, 'd'},
		{"port", required_argument, 0, 'p'},
		{"host", required_argument, 0, 'h'},
		{"file", required_argument, 0, 'f'},
		{"interface", required_argument, 0, 'i'},
		{0, 0, 0 , 0}
	};

	while ((c = getopt_long(argc, argv, "d:p:h:f:i:", long_options, &option_index)) != -1) {
		switch (c) {
			case 0:
				if (long_options[option_index].flag != 0){
					break;
				}
				printf ("option %s", long_options[option_index].name);
				if (optarg) {
					printf (" with arg %s", optarg);
				}
				printf ("\n");
				break;
			case 'd':
				dflag = 1;
				dvalue = optarg;
				break;
			case 'p':
				pflag = 1;
				pvalue = optarg;
				break;
			case 'h':
				hflag = 1;
				hvalue = optarg;
				break;
			case 'f':
				fflag = 1;
				fvalue = optarg;
				break;
			case 'i':
				iflag = 1;
				ivalue = optarg;
				break;
			case '?':
				break;
			default:
				abort();
		}
	}

	sa.sa_handler = handle_write; 
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGUSR1, &sa, NULL) == 1) {
		printf("error %d | %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!dflag) {
		printf("Usage: %s -d [inet | unix | interface] -p [port number] -f [file name] -h [host name]", argv[0]);
		exit(EXIT_FAILURE);
	}


	if (!strcmp(dvalue, "inet")) {
		sockfd = inet(hvalue, pvalue);
	}
	else if (!strcmp(dvalue, "unix")) {
		sockfd = unix_d(fvalue);
	}
	else if (!strcmp(dvalue, "interface")) {
		sockfd = interface(ivalue, pvalue);
	} else {
		printf("unknown domain");
		exit(EXIT_FAILURE);
	}

	memset(recvBuff, '0', sizeof(recvBuff));
	memset(sendBuff, '0', sizeof(sendBuff));

	dmalloc_debug_setup("log-stats,log-non-free, check-fense, check-heap, error-abort,log=cli_logfile.log");

	pid = getpid();
	sprintf(pid_to_send, "%d", pid);
	
	printf("Write quit to terminate\n");
	printf("#>");


	while (fgets(command, BUF_LEN, stdin)) {
		
		gWrite_done = 0; /* reset gWrite_done*/
		if (!strncmp(command,quit,4)) { /* end program when user enters quit*/
			int test;
			test = send(sockfd, pid_to_send, BUF_LEN, 0);
			if (test == -1) {
				printf("failed to send: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			char* quit_a[2];
			quit_a[0] = (char *) malloc(STR_LEN);
			quit_a[1] = (char *) malloc(STR_LEN);
			strcpy(quit_a[0], "2");
			strcpy(quit_a[1], "quit");
			test = send(sockfd, quit_a[0], BUF_LEN, 0);
			if (test == -1) {
				printf("failed to send: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			test = send(sockfd, quit_a[1], BUF_LEN, 0);
			if (test == -1) {
				printf("failed to send: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			free(quit_a[0]);
			free(quit_a[1]);
			test = read(sockfd, recvBuff, BUF_LEN);
			if (test == -1) {
				printf("failed to read quit message: %d | %s \n", errno, strerror(errno));
			}
			break;
		}
		send(sockfd, pid_to_send, BUF_LEN, 0);
		struct params *head;
		init("./main", &head); // init linked list with dummy node
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
		//copy linked list to array
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
			if (strtol(args[0], NULL, 10) == 1) {
				insert_module();
			}
			else if (strtol(args[1], NULL, 10) == 0) {
				remove_module();
			} else {
				printf("unsupported option\n");
				exit(EXIT_FAILURE);
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
			send(sockfd, args[k], BUF_LEN, 0);
		}
		
		while (!gWrite_done) {
			valread = recv(sockfd, recvBuff, BUF_LEN, MSG_WAITALL);
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
		
	}
	
	
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
void handle_write()
{
	gWrite_done = 1;
}

/**
 * @brief load kernel module.
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
 * @brief unload kernel module.
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
 * @brief print kernel buffer.
 * 
 * it searches dmesg output and find
 * last occurence of random number generated by kernel module
 * 
 */
void read_kernel_buffer()
{
	system("dmesg -t | grep \"lkm_example_rand_number\" | tail -1");
}

/**
 * @brief connect IPv4 or IPv6 server.
 * 
 * It finds an address using getaddrinfo. It create a socket
 * and tries to connect for each address. When one of them is
 * successfull it returns socket fd.
 * 
 * @param host host name
 * @param port port number
 * @return int socket fd
 */
int inet(char* host, char* port)
{
	int sockfd = 0, s = 0, rc = 0;

	struct addrinfo hints;
	struct addrinfo *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	s = getaddrinfo(host, port, &hints, &result);
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

	return sockfd;

}
/**
 * @brief connect to unix server.
 * 
 * It creates a unix socket and an address struct with file.
 * Then it connects to file and returns fd.
 * 
 * @param file pathname
 * @return int socket fd
 */
int unix_d(char* file)
{
	int sockfd = 0;

	struct sockaddr_un serv_addr_un;

	memset(&serv_addr_un, 0, sizeof(serv_addr_un));
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("failed to create unix socket in cli: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	serv_addr_un.sun_family = AF_UNIX;
	strcpy(serv_addr_un.sun_path, file);

	if ((connect(sockfd, (struct sockaddr *) &serv_addr_un, sizeof(serv_addr_un))) == -1){
		printf("connect failed in cli: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	return sockfd;
}
/**
 * @brief connect one of the interface address.
 * 
 * It gets all interfaces and find the given interface. After interface is found
 * it tries to find an IPv4 or IPv6 address. Then it creates a socket and connect
 * to the address.
 * 
 * @param interface interface name
 * @param port port number
 * @return int sockfd
 */

int interface(char* interface, char* port)
{
	int family = 0, s = 0, sockfd = 0, rc = 0;
	int domain = AF_INET6;

	char host[NI_MAXHOST];

	struct ifaddrs *ifaddrs, *ifa;
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;
	if (getifaddrs(&ifaddrs) == -1) {
		printf("failed to get interface addresses: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (ifa = ifaddrs; ifa != NULL; ifa=ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (strcmp(ifa->ifa_name, interface)) {
			if (ifa->ifa_next == NULL) {
				domain = AF_INET;
				ifa = ifaddrs;
			}
			continue;
		}

		family = ifa->ifa_addr->sa_family;

		if (!(family == domain)) {
			continue;
		}
		
		s = getnameinfo(ifa->ifa_addr, 
						(family == AF_INET) ? sizeof(struct sockaddr_in) : 
											sizeof(struct sockaddr_in6),
											host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
											
		if (s != 0) {
			printf("get name info failed: %s\n", gai_strerror(s));
		}
		printf("address is = %s\n", host);
		s = getaddrinfo(host, port, &hints, &result);
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

		if (rp == NULL) {
			printf("Could not connect\n");
			exit(EXIT_FAILURE);
		}

		freeaddrinfo(result);
		break;

	}
	freeifaddrs(ifaddrs);
	return sockfd;
}
