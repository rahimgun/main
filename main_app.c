/**
 * @file main_app.c
 * @brief 
 * @version 0.1
 * @date 2021-08-25
 * 
 * @copyright Copyright (c) 2021
 * 
 */

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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dmalloc.h>
#include <sys/types.h>
#include <netdb.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlreader.h>

#define BUF_LEN 1024
#define BACKLOG 10
#define MAX_CLIENT 100

int setParameter(char *parameter, char* value, xmlNode* a_node, xmlDoc* doc, int fd);
void getParameter(char *parameter, xmlNode* a_node, int fd);
void run_command(char *command[], int fd, int size);
void exec_command(char *command[], int fd, int size);
void print_element_names(xmlNode* a_node, int fd);
int isNumber(char* value);
int isIPAddress(char* value);
int isHostname(char* value);

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
	if (argc != 3) {
		fprintf(stderr, "Usage : %s [inet | unix] [port | path name]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	dmalloc_debug_setup("log-stats, log-non-free, check-fense, check-heap, error-abort,log=main_logfile.log");
	int result = 0, rc, en = 1;
	int listenfd = 0, connfd = 0, valread = 0, new_conn = -1;
	int numrv, structsize = 0;
	int timeout, nfds = 1, current_size = 0;
	int END_SERVER = 0, close_conn = 0, compress_array = 0;

	char set[8] = "cli_set";
	char get[8] = "cli_get";
	char run[8] = "cli_run";
	char exec[9] = "cli_exec";
	char quit[5] = "quit";
	char unknown[16] = "unknown method\n";
	char sendBuff[BUF_LEN];
	char recvBuff[BUF_LEN];
	char* done;
	char* end;
	char* docname;

	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL;
	struct sockaddr_in serv_addr, cli_addr;
	struct sockaddr_un serv_addr_un;
	struct pollfd fds[MAX_CLIENT];

	done = "parameter is set\n";
	end = "end of command";
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
	if (!strcmp(argv[1], "inet")) {
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
		if (listenfd == -1) {
			printf("socket() failed: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
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

		memset(&serv_addr, '0', sizeof(serv_addr));
		memset(sendBuff, '0', sizeof(sendBuff));
		memset(recvBuff, '0', sizeof(recvBuff));

		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(atoi(argv[2]));
		memset(&(serv_addr.sin_zero), '\0', 8);

		if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
			printf("failed to bind: %d | %s \n", errno, strerror(errno));
			close(listenfd);
			exit(EXIT_FAILURE);
		}

		if (listen(listenfd, BACKLOG) == -1) {
			printf("failed to listen in main: %d | %s \n", errno, strerror(errno));
			close(listenfd);
			exit(EXIT_FAILURE);
		}
	}
	else if (!strcmp(argv[1], "unix")) {
		listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (listenfd == -1) {
			printf("socket() failed: %d | %s \n", errno, strerror(errno));
			exit(EXIT_FAILURE);
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

		memset(&serv_addr_un, '0', sizeof(serv_addr_un));
		memset(sendBuff, '0', sizeof(sendBuff));
		memset(recvBuff, '0', sizeof(recvBuff));

		serv_addr_un.sun_family = AF_UNIX;
		strcpy(serv_addr_un.sun_path, argv[2]);


		if (bind(listenfd, (struct sockaddr*)&serv_addr_un, sizeof(serv_addr_un)) == -1) {
			printf("failed to bind: %d | %s \n", errno, strerror(errno));
			close(listenfd);
			exit(EXIT_FAILURE);
		}

		if (listen(listenfd, BACKLOG) == -1) {
			printf("failed to listen in main: %d | %s \n", errno, strerror(errno));
			close(listenfd);
			exit(EXIT_FAILURE);
		}
	}
	memset(fds, 0, sizeof(fds));

	fds[0].fd = listenfd;
	fds[0].events = POLLIN;

	timeout = (10 * 60 * 1000);
	int i = 0, j = 0;
	structsize = sizeof(cli_addr);
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
				printf("error. revent = %x fd = %d\n", fds[i].revents, fds[i].fd);
				END_SERVER = 1;
				break;
			}

			if (fds[i].fd == listenfd) {
				do {
					new_conn = accept(listenfd, NULL, NULL);
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
				//do {
				//printf("test %d %d\n", fds[i].fd, fds[i].revents);
				close_conn = 0;
				valread = read(fds[i].fd, recvBuff, BUF_LEN);
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
				valread = read(fds[i].fd, recvBuff, BUF_LEN);
				if (valread == -1) {
					printf("failed to read size: %d | %s \n", errno, strerror(errno));
					exit(EXIT_FAILURE);
				}
				int k = 0;
				int size = atoi(recvBuff);
				memset(recvBuff, 0, BUF_LEN);
				printf("size = %d\n",size);
				valread = read(fds[i].fd, recvBuff, BUF_LEN);
				if (valread == -1) {
					printf("failed to read method: %d | %s \n", errno, strerror(errno));
					exit(EXIT_FAILURE);
				}
				char* method = (char *) malloc(valread);
				strncpy(method, recvBuff, valread);
				memset(recvBuff, 0, BUF_LEN);
				char* args[size - 1];
				printf("method = %s\n", method);
				for (k = 0 ; k < size - 2; k++) {
					valread = read(fds[i].fd, recvBuff, BUF_LEN);
					if (valread == -1) {
						printf("failed to read options:  %d | %s \n", errno, strerror(errno));
						exit(EXIT_FAILURE);
					}
					args[k] = (char *) malloc(valread);
					strcpy(args[k],recvBuff);
					memset(recvBuff, 0, BUF_LEN);
					//printf("args = %s\n",args[k]);
				}
				
				if (!(result = strncmp(set, method, 7))) {
					setParameter(args[0], args[1], root_element, doc, fds[i].fd);
					kill(cli_pid, SIGUSR1);
					//break;
				}
				else if (!(result = strncmp(get, method, 7))) {
					getParameter(args[0], root_element, fds[i].fd);
					kill(cli_pid, SIGUSR1);
					//break;
				}
				else if (!(result = strncmp(run, method, 7))) {
					exec_command(args, fds[i].fd, size-2);
					kill(cli_pid, SIGUSR1);
					//break;
				}
				else if (!(result = strncmp(exec, method, 7))) {
					exec_command(args, fds[i].fd, size-2);
					kill(cli_pid, SIGUSR1);
					//break;
				} 
				else if (!(result = strncmp(quit, method, 4))) {
					close_conn = 1;
					printf("quit\n");
					for (k = 0 ; k < size-2 ; k++) {
						free(args[k]);
					}
					free(method);
					memset(recvBuff, 0, BUF_LEN);
					//break;
				} else {
					send(fds[i].fd, unknown, strlen(unknown), 0);
					kill(cli_pid, SIGUSR1);
					//break;
				}
				for (k = 0 ; k < size-2 ; k++) {
					free(args[k]);
				}
				free(method);
				memset(recvBuff, 0, BUF_LEN);
				//} while (1);
				//printf("test-else %d\n", close_conn);
				if (close_conn) {
					close(fds[i].fd);
					fds[i].fd = -1;
					compress_array = 1;
				}
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
	} while (END_SERVER == 0);


	/*
	connfd = accept(listenfd, (struct sockaddr*)&cli_addr, &structsize);
	if (connfd == -1) {
		printf("failed to listen in main: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	valread = read(connfd, recvBuff, BUF_LEN);
	pid_t cli_pid = atoi(recvBuff);
	if (cli_pid == -1) {
		printf("cannot receive pid of cli\n");
		exit(EXIT_FAILURE);
	}
	while (1) {
		valread = read(connfd, recvBuff, BUF_LEN);
		int i = 0;
		int size = atoi(recvBuff);
		char* args[size - 1];
		valread = read(connfd, recvBuff, BUF_LEN);
		char* method = (char *) malloc(valread);
		strncpy(method, recvBuff, valread);
		for (i = 0 ; i < size - 2; i++) {
			valread = read(connfd, recvBuff, BUF_LEN);
			args[i] = (char *) malloc(valread);
			strcpy(args[i],recvBuff);
		}
		
		if (!(result = strncmp(set, method, 7))) {
			setParameter(args[0], args[1], root_element, doc, connfd);
			kill(cli_pid, SIGUSR1);
		}
		else if (!(result = strncmp(get, method, 7))) {
			getParameter(args[0], root_element, connfd);
			kill(cli_pid, SIGUSR1);
		}
		else if (!(result = strncmp(run, method, 7))) {
			exec_command(args, connfd, size-2);
			kill(cli_pid, SIGUSR1);
		}
		else if (!(result = strncmp(exec, method, 7))) {
			exec_command(args, connfd, size-2);
			kill(cli_pid, SIGUSR1);
		} 
		else if (!(result = strncmp(quit, method, 4))) {
			printf("quit\n");
			for (i = 0 ; i < size-2 ; i++) {
				free(args[i]);
			}
			free(method);
			break;
		} else {
			send(connfd, unknown, strlen(unknown), 0);
			kill(cli_pid, SIGUSR1);
		}
		for (i = 0 ; i < size-2 ; i++) {
			free(args[i]);
		}
		free(method);
	}
	if (close(connfd) == -1) {
		printf("error closing connfd: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	*/

	if (close(listenfd) == -1) {
		printf("error closing listenfd: %d | %s \n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	xmlFreeDoc(doc);
	xmlCleanupParser();
	dmalloc_shutdown();
	return 0;
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
	char* test = parameter;
	char* token = NULL;
	char* temp = NULL;
	char* invalid = NULL;
	char* set = NULL;
	char* notFound = NULL;
	xmlChar* key = NULL;
	xmlChar* type = NULL;
	char* newValue = NULL;
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
			xmlNodeSetContent(node, (const xmlChar*) value);
			xmlSaveFormatFile("./example.xml",doc,1);
			send(fd, set, strlen(set), 0);
		} else {
			send(fd, invalid, strlen(invalid), 0);
		}
	} 
	else if (!xmlStrcmp(type, (const xmlChar*) "int")) {
		if (isNumber(value)) {
			xmlNodeSetContent(node, (const xmlChar*) value);
			xmlSaveFormatFile("./example.xml",doc,1);
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
					xmlNodeSetContent(node, (const xmlChar*) value);
					xmlSaveFormatFile("./example.xml",doc,1);
					send(fd, set, strlen(set), 0);
				} else {
					send(fd, invalid, strlen(invalid), 0);
				}
			}
		} else {
			xmlNodeSetContent(node, (const xmlChar*) value);
			xmlSaveFormatFile("./example.xml",doc,1);
			send(fd, set, strlen(set), 0);
		}
		free(syntax);
	}
	free(type);
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
			free(key);

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
			free(key);
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