/**
 * @file main_app.c
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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <sys/un.h>
#include <regex.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <getopt.h>
#include <dmalloc.h>
#include <sys/types.h>
#include <netdb.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlreader.h>

#define BUF_LEN 1024
#define BACKLOG 10
#define MAX_CLIENT 100

struct fd {
	int t_fd;
	xmlNode* node;
	xmlDoc* doc;
};


void *handle_command(void *args);
int inet6(char* port);
int inet4(char* host, char* port);
int unix_d(char* file);
int interface(char* interface, char* port);
int setParameter(char *parameter, char* value, xmlNode* a_node, xmlDoc* doc, int fd);
void getParameter(char *parameter, xmlNode* a_node, int fd);
void run_command(char *command[], int fd, int size);
void exec_command(char *command[], int fd, int size);
void print_element_names(xmlNode* a_node, int fd);
int isNumber(char* value);
int isIPAddress(char* value);
int isHostname(char* value);

pthread_mutex_t mutexsave;

/**
 * @brief calls corresponding functions for methods
 * 
 * It performs necessary operations for socket communication and
 * xml document parsing. If xml file doesn't exist or contain nothing
 * terminates the program. Then it sets up IP address with given port number
 * and all local address and starts to listen the port. Firstly it gets
 * pid of CLI to send signal to writing is done. Then it enters an infinity
 * loop. In each loop, it gets one command from CLI. It gets size of command
 * and method name. It creates a string array and puts options to array from 
 * read buffer. Finally it calls function that matches with method name. After function
 * ends sends signal to CLI and starts to wait new command. 
 * 
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char **argv)
{
	/*
	if (!(argc > 2 && argc < 5)) {
		fprintf(stderr, "Usage : %s [inet | unix ] [hostname port | path name ]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	*/

	dmalloc_debug_setup("log-stats, log-non-free, check-fense, check-heap, error-abort,log=main_logfile.log");
	int result = 0, rc = 0;
	int dflag = 0, pflag = 0, hflag = 0, fflag = 0, iflag = 0;
	int index, c;
	int option_index = 0;
	int listenfd = 0, new_conn = -1;
	int structsize = 0;
	int timeout, nfds = 1, current_size = 0;
	int END_SERVER = 0, close_conn = 0, compress_array = 0;
	double cpu_time_used;

	char sendBuff[BUF_LEN];
	char recvBuff[BUF_LEN];
	char client_addr[INET6_ADDRSTRLEN];
	char host[NI_MAXHOST];
	char* docname;
	char *dvalue = NULL, *pvalue = NULL, *hvalue = NULL, *fvalue = NULL, *ivalue = NULL;

	clock_t start, finish;
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL;

	struct sockaddr_storage addr;
	struct pollfd fds[MAX_CLIENT];

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

	docname = "./example.xml";

	doc = xmlParseFile(docname);
	
	//doc = xmlReaderForFile(docname,NULL,0);
	if (doc == NULL) {
		fprintf(stderr, "Document not parsed.\n");
		exit(EXIT_FAILURE);
	}
	root_element = xmlDocGetRootElement(doc);
	if (root_element == NULL) {
		printf("empty document");
		xmlFreeDoc(doc);
		exit(EXIT_FAILURE);
	}

	pthread_mutex_init(&mutexsave, NULL);

	memset(sendBuff, '0', sizeof(sendBuff));
	memset(recvBuff, '0', sizeof(recvBuff));

	if (!strcmp(dvalue, "inet6")) {
		listenfd = inet6(pvalue);
	}
	else if (!strcmp(dvalue, "inet4")) {
		listenfd = inet4(hvalue, pvalue);
	}
	else if (!strcmp(dvalue, "unix")) {
		listenfd = unix_d(fvalue);
	}
	else if (!strcmp(dvalue, "interface")) {
		listenfd = interface(ivalue, pvalue);
	}
	
	memset(fds, 0, sizeof(fds));

	fds[0].fd = listenfd;
	fds[0].events = POLLIN;

	timeout = (10 * 60 * 1000);
	int i = 0, j = 0;
	structsize = sizeof(addr);
	do {
		rc = poll(fds, nfds, timeout);
		if (rc == -1) {
			printf("failed to poll: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (rc == 0) {
			printf("poll timed out\n");
			break;
		}

		current_size = nfds;
		for (i = 0 ; i < current_size; i++) {
			if (fds[i].revents == 0) {
				continue;
			}

			if (fds[i].revents != POLLIN) {
				printf("error. revent = %d fd = %d\n", fds[i].revents, fds[i].fd);
				END_SERVER = 1;
				break;
			}

			if (fds[i].fd == listenfd) {
				do {
					//new_conn = accept(listenfd, NULL, NULL);
					new_conn = accept(listenfd, (struct sockaddr *) &addr, &structsize);
					if (new_conn < 0) {
						if (errno != EWOULDBLOCK) {
							END_SERVER = 1;
						}
						break;
					}

					printf("new connection with fd = %d\n", new_conn);
					fds[nfds].fd = new_conn;
					fds[nfds].events = POLLIN;
					nfds++;
				} while(new_conn != -1);
			} else {
					pthread_t thread;
					struct fd t_fd;
					t_fd.t_fd = fds[i].fd;
					t_fd.node = root_element;
					t_fd.doc = doc;
					if (pthread_create(&thread, NULL, handle_command, &t_fd) != 0) {
						printf("failed to create thread: %d | %s \n", errno, strerror(errno));
						exit(EXIT_FAILURE);
					}
					void *ret;
					if (pthread_join(thread, &ret) != 0) {
						printf("failed to join thread: %d | %s \n", errno, strerror(errno));
						exit(EXIT_FAILURE);
					}
					
					if (!strcmp(ret, "yes")) {
						close(fds[i].fd);
						fds[i].fd = -1;
						compress_array = 1;
					} 
				}
			int l, m;
			if (compress_array) {
				compress_array = 0;
				for (l = 0; l < nfds; l++) {
					if (fds[l].fd == -1) {
						for(m = l; m < nfds-1; m++) {
							fds[m].fd = fds[m+1].fd;
						}
						l--;
						nfds--;
						}
					}
			}
		}
	} while (END_SERVER == 0);


	if (close(listenfd) == -1) {
		printf("error closing listenfd: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	pthread_mutex_destroy(&mutexsave);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	dmalloc_shutdown();
	return 0;
}

/**
 * @brief create an IPv6 connection
 * 
 * It creates an IPv6 socket. It listens any IPv6 address that also 
 * accepts IPv4 clients.
 * 
 * @param port port number
 * @return int socket fd
 */

int inet6(char* port) {
	int listenfd = 0, en = 1, rc = 0, s = 0;

	struct addrinfo hints;
	struct addrinfo *result_addr, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	s = getaddrinfo(NULL, port, &hints, &result_addr);
	if (s != 0) {
		printf("get addr info failed: %s \n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}
	
	for (rp = result_addr; rp != NULL; rp = rp->ai_next) {
		
		listenfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if (listenfd == -1) {
			continue;
		}

		rc = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char*)&en, sizeof(en));
		if (rc == -1) {
			printf("failed to set socket option: %d | %s \n", errno, strerror(errno));
			close(listenfd);
			exit(EXIT_FAILURE);
		}

		rc = ioctl(listenfd, FIONBIO, (char*)&en);

		if (rc == -1) {
			printf("failed to set socket to nonblocking: %d | %s \n", errno, strerror(errno));
			close(listenfd);
			exit(EXIT_FAILURE);
		}

		if (bind(listenfd, rp->ai_addr, rp->ai_addrlen) == 0) {
			break;
		}

		close(listenfd);
	}

	freeaddrinfo(result_addr);

	if (rp == NULL) {
		printf("Could not bind\n");
		exit(EXIT_FAILURE);
	}

	if (listen(listenfd, BACKLOG) == -1) {
		printf("failed to listen in main: %d | %s \n", errno, strerror(errno));
		close(listenfd);
		exit(EXIT_FAILURE);
	}
	return listenfd;
}

/**
 * @brief create an IPv4 connection
 * 
 * It finds addresses with given host name. It creates an IPv4 socket and bind to 
 * the first address it found.
 * 
 * @param host host name
 * @param port port number
 * @return int socket fd
 */

int inet4(char* host, char* port)
{
	int listenfd = 0, en = 1, s = 0, rc = 0;

	struct addrinfo hints;
	struct addrinfo *result_addr, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;
	s = getaddrinfo(host, port, &hints, &result_addr);
	if (s != 0) {
		printf("get addr info failed: %s \n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	for (rp = result_addr; rp != NULL; rp = rp->ai_next) {
		listenfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if (listenfd == -1) {
			continue;
		}

		rc = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char*)&en, sizeof(en));
		if (rc == -1) {
			printf("failed to set socket option: %d | %s \n", errno, strerror(errno));
			close(listenfd);
			exit(EXIT_FAILURE);
		}

		rc = ioctl(listenfd, FIONBIO, (char*)&en);

		if (rc == -1) {
			printf("failed to set socket to nonblocking: %d | %s \n", errno, strerror(errno));
			close(listenfd);
			exit(EXIT_FAILURE);
		}

		if (bind(listenfd, rp->ai_addr, rp->ai_addrlen) == 0) {
			break;
		}

		close(listenfd);
	}

	freeaddrinfo(result_addr);

	if (rp == NULL) {
		printf("Could not bind\n");
		exit(EXIT_FAILURE);
	}

	if (listen(listenfd, BACKLOG) == -1) {
		printf("failed to listen in main: %d | %s \n", errno, strerror(errno));
		close(listenfd);
		exit(EXIT_FAILURE);
	}

	return listenfd;
}
/**
 * @brief create a unix domain socket
 * 
 * It creates a unix socket and a unix socket address struct with given path name.
 * Then it binds socket to address.
 * 
 * @param file pathname 
 * @return int socket fd
 */
int unix_d(char* file)
{
	int listenfd = 0, en = 1, rc = 0;

	struct sockaddr_un serv_addr_un;

	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listenfd == -1) {
		printf("socket() failed: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	rc = ioctl(listenfd, FIONBIO, (char*)&en);

	if (rc == -1) {
		printf("failed to set socket to nonblocking(unix): %d | %s \n", errno, strerror(errno));
		close(listenfd);
		exit(EXIT_FAILURE);
	}

	memset(&serv_addr_un, '0', sizeof(serv_addr_un));


	serv_addr_un.sun_family = AF_UNIX;
	strcpy(serv_addr_un.sun_path, file);


	if (bind(listenfd, (struct sockaddr*)&serv_addr_un, sizeof(serv_addr_un)) == -1) {
		printf("failed to bind (unix): %d | %s \n", errno, strerror(errno));
		close(listenfd);
		exit(EXIT_FAILURE);
	}

	if (listen(listenfd, BACKLOG) == -1) {
		printf("failed to listen in main(unix): %d | %s \n", errno, strerror(errno));
		close(listenfd);
		exit(EXIT_FAILURE);
	}

	return listenfd;
}

/**
 * @brief open socket with an address of given interface
 * 
 * It gets all interfaces and find the given interface. After interface is found
 * it tries to find an IPv4 or IPv6 address. Then it creates a socket and bind it
 * to the address.
 * 
 * @param interface interface name
 * @param port port number
 * @return int socket fd
 */

int interface(char* interface, char* port)
{
	int family = 0, s = 0, listenfd = 0, rc = 0, en = 1;

	char host[NI_MAXHOST];

	struct ifaddrs *ifaddrs, *ifa;
	struct addrinfo hints;
	struct addrinfo *result_addr, *rp;

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
			continue;
		}

		family = ifa->ifa_addr->sa_family;

		if (!(family == AF_INET || family == AF_INET6)) {
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
		s = getaddrinfo(host, port, &hints, &result_addr);

		if (s != 0) {
			printf("get addr info failed: \n", gai_strerror(s));
		}

		for (rp = result_addr; rp != NULL; rp = rp->ai_next) {

			listenfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

			if (listenfd == -1) {
				printf("failed to create socket(interface): %d | %s \n", errno, strerror(errno));
				continue;
			}

			rc = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char*)&en, sizeof(en));

			if (rc == -1) {
				printf("failed to set socket option: %d | %s \n", errno, strerror(errno));
				close(listenfd);
				exit(EXIT_FAILURE);
			}

			rc = ioctl(listenfd, FIONBIO, (char*)&en);

			if (rc == -1) {
				printf("failed to set socket to nonblocking: %d | %s \n", errno, strerror(errno));
				close(listenfd);
				exit(EXIT_FAILURE);
			}

			rc = bind(listenfd, rp->ai_addr, rp->ai_addrlen);
			if (rc == -1) {
				printf("failed to bind(interface): %d | %s \n", errno, strerror(errno));
				close(listenfd);
				exit(EXIT_FAILURE);
			} else {
				break;
			}

		}
		if (listen(listenfd, BACKLOG) == -1) {
			printf("failed to listen in main: %d | %s \n", errno, strerror(errno));
			close(listenfd);
			exit(EXIT_FAILURE);
		}
		freeaddrinfo(result_addr);
		break;
	}
	freeifaddrs(ifaddrs);
	return listenfd;
}

/**
 * @brief Set the parameter value
 * 
 * It finds the node for given parameter and checks node's type.
 * It validates the value depending on the type. If value is valid
 * it sets the node's content. It notifies user about operation result.
 * 
 * @param parameter full path of the parameter
 * @param value new value for the parameter
 * @param a_node root node of the document
 * @param doc document to save new file
 * @param fd socket fd to send inform messages
 * @retval 0: parameter is not found
 * @retval 1: parameter is set
 */
int setParameter(char *parameter, char* value, xmlNode* a_node, xmlDoc* doc, int fd)
{
	int ret = 0;

	char* test = parameter;
	char* token = NULL;
	char* temp = NULL;
	char* invalid = NULL;
	char* set = NULL;
	char* notFound = NULL;
	char* newValue = NULL;
	xmlChar* key = NULL;
	xmlChar* type = NULL;
	xmlNode* node = a_node;

	invalid = "type is not valid\n";
	set = "parameter is set\n";
	notFound = "parameter is not found\n";

	token = strtok(test, ".");
	while (token != NULL) {
		if (node->type != XML_ELEMENT_NODE) {
			if (node->next != NULL) {
				node = node->next;
				continue;
			} else {
				send(fd, notFound, strlen(notFound), 0);
				return 0;
			}
		}

		if (xmlStrcmp(node->name, (const xmlChar*)token)) {
			if (node->next != NULL) {
				node = node->next;
				continue;
			} else {
				send(fd, notFound, strlen(notFound), 0);
				return 0;
			}
		}

		node = node->children;
		token = strtok(NULL, ".");
	}
	type = xmlGetProp(node->parent, "type");
	if (!xmlStrcmp(type, (const xmlChar*) "boolean")) {
		if (!strcmp("true", value) || !strcmp("false", value)) {
			ret = pthread_mutex_lock(&mutexsave);
			if (ret != 0) {
				printf("failed to lock mutex: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			xmlNodeSetContent(node, (const xmlChar*) value);
			xmlSaveFormatFile("./example.xml",doc,1);
			ret = pthread_mutex_unlock(&mutexsave);
			if (ret != 0) {
				printf("failed to unlock mutex: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			send(fd, set, strlen(set), 0);
		} else {
			send(fd, invalid, strlen(invalid), 0);
		}
	} 
	else if (!xmlStrcmp(type, (const xmlChar*) "int")) {
		if (isNumber(value)) {
			ret = pthread_mutex_lock(&mutexsave);
			if (ret != 0) {
				printf("failed to lock mutex: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			xmlNodeSetContent(node, (const xmlChar*) value);
			xmlSaveFormatFile("./example.xml",doc,1);
			ret = pthread_mutex_unlock(&mutexsave);
			if (ret != 0) {
				printf("failed to unlock mutex: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			send(fd, set, strlen(set), 0);
		} else {
			send(fd, invalid, strlen(invalid), 0);
		}
	} 
	else if (!xmlStrcmp(type, (const xmlChar*) "string")) {
		xmlChar* syntax = xmlGetProp(node->parent, "syntax");
		if (syntax != NULL) {
			if (!xmlStrcmp(syntax, (const xmlChar*) "IPAddress")) {
				if (isIPAddress(value) || isHostname(value)){
					ret = pthread_mutex_lock(&mutexsave);
					if (ret != 0) {
						printf("failed to lock mutex: %d | %s \n", errno, strerror(errno));
						exit(EXIT_FAILURE);
					}
					xmlNodeSetContent(node, (const xmlChar*) value);
					xmlSaveFormatFile("./example.xml",doc,1);
					ret = pthread_mutex_unlock(&mutexsave);
					if (ret != 0) {
						printf("failed to unlock mutex: %d | %s \n", errno, strerror(errno));
						exit(EXIT_FAILURE);
					}
					send(fd, set, strlen(set), 0);
				} else {
					send(fd, invalid, strlen(invalid), 0);
				}
			}
		} else {
			ret = pthread_mutex_lock(&mutexsave);
			if (ret != 0) {
				printf("failed to lock mutex: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			xmlNodeSetContent(node, (const xmlChar*) value);
			xmlSaveFormatFile("./example.xml",doc,1);
			ret = pthread_mutex_unlock(&mutexsave);
			if (ret != 0) {
				printf("failed to unlock mutex: %d | %s \n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
			send(fd, set, strlen(set), 0);
		}
		xmlFree(syntax);
	}
	xmlFree(type);
	return 1;
}
/**
 * @brief Get the parameter content from xml
 * 
 * It tokenizes parameter with dot. It searches xml nodes for each token.
 * When it finds a match, it moves to the children node with new token.
 * After it completes tokenization, it checks if child is a leaf node.
 * It prints leaf node's content, otherwise calls print_element_names(xmlNode*, int)
 * to print all nodes.
 * 
 * @param parameter full path of the parameter
 * @param a_node root node of the document
 * @param fd socket fd to write parameter content
 */
void getParameter(char *parameter, xmlNode* a_node, int fd)
{
	int flag = 1;
	char* token = NULL;
	char* invalid = "parameter is not found\n";
	xmlChar* key = NULL;
	xmlNode* node = a_node;

	token = strtok(parameter, ".");
	while (token != NULL) {
		if (node->type != XML_ELEMENT_NODE) {
			if (node->next != NULL) {
				node = node->next;
				continue;
			} else {
				send(fd, invalid, strlen(invalid), 0);
				flag = 0;
				break;
			}
		}

		if (xmlStrcmp(node->name, (const xmlChar*)token)) {
			if (node->next != NULL) {
				node = node->next;
				continue;
			} else {
				send(fd, invalid, strlen(invalid), 0);
				flag = 0;
				break;
			}
		}

		node = node->children;
		token = strtok(NULL, ".");
	}
	if (flag) {
	//printf("%d", node->type);
		if (node->next == NULL) {
			xmlChar* key = xmlNodeGetContent(node);
			send(fd, key, xmlStrlen(key), 0);
			xmlFree(key);

		} else {
			print_element_names(node, fd);
		}
	}
}
/**
 * @brief runs commands
 * 
 * @param command contains command and options
 * @param fd socket fd to write output
 * @param size size of command list
 */
void run_command(char *command[], int fd, int size)
{
	int link[2] = {0};
	int nbytes = 0;
	int i = 0;
	char output[4096] = {0};
	char *temp = NULL;
	pid_t pid;
	command[size] = NULL;
	
	
	if (pipe(link) == -1) {
		printf("error: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	pid = fork();

	if (pid == -1) {
		printf("error: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		if (close(link[0]) == -1) {
			printf("error: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (dup2(link[1], STDOUT_FILENO) == -1) {
			printf("error: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (close(link[1]) == -1) {
			printf("error: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		execvp(command[0],command);
	} else {
		if (close(link[1]) == -1) {
			printf("error: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		nbytes = read(link[0], output, sizeof(output));
		send(fd, output, nbytes, 0);
		//printf("%.*s", nbytes, output);
		wait(NULL);
	}
}
/**
 * @brief executing user's shell scripts
 * 
 * It executes scripts with execvp. It puts NULL to the end of command list.
 * It creates a pipe to communicate with the script. When this command forks,
 * parent process starts to waiting script result. It sends result to CLI with
 * socket. Child process duplicates the write end of the pipe to STDOUT. Parent reads
 * from pipe when script writes to STDOUT.
 * 
 * @param command string array of command and options
 * @param fd socket fd to write command' result
 * @param size counf of the command and options in command[]
 */
void exec_command(char *command[], int fd, int size)
{
	int link[2] = {0};
	int nbytes = 0;
	int i = 0;
	char output[4096] = {0};
	char *temp = NULL;
	
	command[size] = NULL;
	pid_t pid;

	if (pipe(link) == -1) {
		printf("error: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid == -1) {
		printf("error: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		if (close(link[0]) == -1) {
			printf("error: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (dup2(link[1], STDOUT_FILENO) == -1) {
			printf("error: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (close(link[1]) == -1) {
			printf("error: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		execvp(command[0], command);
	} else {
		if (close(link[1]) == -1) {
			printf("error: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		nbytes = read(link[0], output, sizeof(output));
		//printf("%.*s", nbytes, output);
		send(fd, output, nbytes, 0);
		wait(NULL);
	}
}
/**
 * @brief printing node contents when partial path is given
 * 
 * It finds child nodes recursively and print
 * name and content of the node.
 * 
 * @param a_node top node of the partial path
 * @param fd socket fd to write parameter' content
 */
void print_element_names(xmlNode * a_node, int fd)
{
	char* newline = "\n";
	char* colon = ":";
	xmlNode *cur_node = NULL;
	for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			xmlChar* key = xmlNodeGetContent(cur_node->children);
			const xmlChar* name = cur_node->name;
			if (key != NULL) {
				
				if (send(fd, name, xmlStrlen(name), 0) == -1) {
					printf("failed to send %d | %s \n", errno, strerror(errno));
				}
				
				if (send(fd, colon, strlen(colon), 0) == -1) {
					printf("failed to send %d | %s \n", errno, strerror(errno));
				}
				if (send(fd, key, xmlStrlen(key), 0) == -1) {
					printf("failed to send %d | %s \n", errno, strerror(errno));
				}
				if (send(fd, newline, strlen(newline), 0) == -1) {
					printf("failed to send %d | %s \n", errno, strerror(errno));
				}
				sleep(0.1);
				//printf("name: %s value = %s\n", cur_node->name, key);
			}
			xmlFree(key);
		}
		print_element_names(cur_node->children, fd);
	}	
}

/**
 * @brief check if value is number.
 * 
 * It checks every character of the value to the end.
 * When it encounters a non-digit value return 0.
 * 
 * @return int 
 * @param value 
 * @retval 0: not a number
 * @retval 1: value is a number
 */
int isNumber(char* value)
{
	int i = 0;
	for (i = 0 ; value[i] != '\0' ; i++) {
		if (isdigit(value[i]) == 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief it checks if value is a valid IPv4 or IPv6 address.
 * 
 * It uses inet_pton to create a network address. It determines
 * address is valid if one of them convert value to network format
 * successfully.
 * 
 * @param value 
 * @return int 
 * @retval 0: not a valid IPv4 or IPv6 address
 * @retval 1: valid IPv4 or IPv6 address
 */
int isIPAddress(char* value)
{
	unsigned char buf[sizeof(struct in6_addr)];
	int result = 0;
	result = (inet_pton(AF_INET, value, buf) || inet_pton(AF_INET6, value, buf));
	return result;
}
/**
 * @brief check value if a valid hostname
 * 
 * It creates a regex for hostname validation.
 * If compilation of regex is successfull it executes
 * regex with the value and return.
 * 
 * @param value 
 * @return int 
 * @retval 0: invalid hostname
 * @retval 1: valid hostname
 */
int isHostname(char *value)
{
	regex_t regex;
	int reti = 0;
	char* reg = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$";
	reti = regcomp(&regex, reg, REG_EXTENDED|REG_NOSUB);
	
	if (reti) {
		printf("failed to compile regex\n");
		exit(1);
	}

	reti = regexec(&regex, value, (size_t) 0, NULL, 0);
	regfree(&regex);
	if (!reti) {
		return 1;
	}
	else if (reti == REG_NOMATCH) {
		return 0;
	}
}

void *handle_command(void *args)
{
	printf("thread id = %u \n", pthread_self());
	struct fd *t_fd = (struct fd*) args;
	int fd = t_fd->t_fd;
	int valread;
	int result;
	double cpu_time_used;

	xmlDoc* doc = t_fd->doc;
	xmlNode* root_element = t_fd->node;
	clock_t start, finish;
	char *ret;
	char set[8] = "cli_set";
	char get[8] = "cli_get";
	char run[8] = "cli_run";
	char exec[9] = "cli_exec";
	char quit[5] = "quit";
	char unknown[16] = "unknown method\n";
	char sendBuff[BUF_LEN];
	char recvBuff[BUF_LEN];
	ret = (char *) malloc(20);
	strcpy(ret, "no");
	start = clock();
	valread = read(fd, recvBuff, BUF_LEN);
	if (valread == -1) {
		printf("failed to read cli pid: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	pid_t cli_pid = atoi(recvBuff);
	memset(recvBuff, 0, BUF_LEN);
	printf("pid = %d\n", cli_pid);
	if (cli_pid == -1) {
		printf("cannot receive pid of cli\n");
		exit(EXIT_FAILURE);
	}
	valread = read(fd, recvBuff, BUF_LEN);
	if (valread == -1) {
		printf("failed to read size: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	int k = 0;
	int size = atoi(recvBuff);
	memset(recvBuff, 0, BUF_LEN);
	printf("size = %d\n",size);
	valread = read(fd, recvBuff, BUF_LEN);
	if (valread == -1) {
		printf("failed to read method: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	char* method = (char *) malloc(valread);
	strncpy(method, recvBuff, valread);
	memset(recvBuff, 0, BUF_LEN);
	char* args_t[size - 1];
	printf("method = %s\n", method);
	for (k = 0 ; k < size - 2; k++) {
		valread = read(fd, recvBuff, BUF_LEN);
		if (valread == -1) {
			printf("failed to read options:  %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		args_t[k] = (char *) malloc(valread);
		strcpy(args_t[k],recvBuff);
		memset(recvBuff, 0, BUF_LEN);
		//printf("args = %s\n",args[k]);
	}
	
	if (!(result = strncmp(set, method, 7))) {
		setParameter(args_t[0], args_t[1], root_element, doc, fd);
		kill(cli_pid, SIGUSR1);
		//break;
	}
	else if (!(result = strncmp(get, method, 7))) {
		getParameter(args_t[0], root_element, fd);
		kill(cli_pid, SIGUSR1);
		//break;
	}
	else if (!(result = strncmp(run, method, 7))) {
		exec_command(args_t, fd, size-2);
		kill(cli_pid, SIGUSR1);
		//break;
	}
	else if (!(result = strncmp(exec, method, 7))) {
		exec_command(args_t, fd, size-2);
		kill(cli_pid, SIGUSR1);
		//break;
	} 
	else if (!(result = strncmp(quit, method, 4))) {
		strcpy(ret, "yes");
		//printf("quit\n");
		//for (k = 0 ; k < size-2 ; k++) {
		//	free(args_t[k]);
		//}
		//free(method);
		//memset(recvBuff, 0, BUF_LEN);
		//break;
	} else {
		send(fd, unknown, strlen(unknown), 0);
		kill(cli_pid, SIGUSR1);
		//break;
	}
	for (k = 0 ; k < size-2 ; k++) {
		free(args_t[k]);
	}
	finish = clock();
	cpu_time_used = ((double) (finish - start)) / CLOCKS_PER_SEC;
	printf("command took %f seconds\n", cpu_time_used);
	free(method);
	memset(recvBuff, 0, BUF_LEN);
	//} while (1);
	//printf("test-else %d\n", close_conn);
	/*
	if (close_conn) {
		close(fds[i].fd);
		fds[i].fd = -1;
		compress_array = 1;
	}
	*/
	pthread_exit(ret);
}