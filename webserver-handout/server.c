#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>

#define DEFAULT_PORT	"8080"
#define DEFAULT_CONFIG	"http.conf"
#define BUFFER_MAX	1024

void usage(char* name);
int create_server_socket(char* port, int protocol);
int run_server(char* config_path, char* port, int verbose_flag);
void handle_client(int sock, struct sockaddr_storage client_addr, socklen_t addr_len);

int run_server(char* config_path, char* port, int verbose_flag) {
	int sock = create_server_socket(port, SOCK_STREAM);
	
	while (1) {
		struct sockaddr_storage client_addr;
		socklen_t client_addr_len = sizeof(client_addr);
		int client = accept(sock, (struct sockaddr*)&client_addr, &client_addr_len);
		if (client == -1) {
			perror("accept");
			continue;
		}
		handle_client(client, client_addr, client_addr_len);
	}
	return 0;
}

void handle_client(int sock, struct sockaddr_storage client_addr, socklen_t addr_len) {
	unsigned char buffer[BUFFER_MAX];
	char client_hostname[NI_MAXHOST];
	char client_port[NI_MAXSERV];
	int ret = getnameinfo((struct sockaddr*)&client_addr, addr_len, client_hostname,
		       NI_MAXHOST, client_port, NI_MAXSERV, 0);
	if (ret != 0) {
		fprintf(stderr, "Failed in getnameinfo: %s\n", gai_strerror(ret));
	}
	printf("Got a connection from %s:%s\n", client_hostname, client_port);
	while (1) {
		int bytes_read = recv(sock, buffer, BUFFER_MAX-1, 0);
		if (bytes_read == 0) {
			printf("Peer disconnected\n");
			close(sock);
			return;
		}
		if (bytes_read < 0) {
			perror("recv");
			continue;
		}
		buffer[bytes_read] = '\0';
		printf("received: %s\n", buffer);
		send(sock, buffer, strlen(buffer)+1, 0);
	}
	return;
}

int create_server_socket(char* port, int protocol) {
	int sock;
	int ret;
	int optval = 1;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = protocol;
	/* AI_PASSIVE for filtering out addresses on which we
	 * can't use for servers
	 *
	 * AI_ADDRCONFIG to filter out address types the system
	 * does not support
	 *
	 * AI_NUMERICSERV to indicate port parameter is a number
	 * and not a string
	 *
	 * */
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;
	/*
	 *  On Linux binding to :: also binds to 0.0.0.0
	 *  Null is fine for TCP, but UDP needs both
	 *  See https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
	 */
	ret = getaddrinfo(protocol == SOCK_DGRAM ? "::" : NULL, port, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
		if (sock == -1) {
			perror("socket");
			continue;
		}

		// Allow us to quickly reuse the address if we shut down (avoiding timeout)
		ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		if (ret == -1) {
			perror("setsockopt");
			close(sock);
			continue;
		}

		ret = bind(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
		if (ret == -1) {
			perror("bind");
			close(sock);
			continue;
		}
		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "Failed to find a suitable address for binding\n");
		exit(EXIT_FAILURE);
	}

	if (protocol == SOCK_DGRAM) {
		return sock;
	}
	// Turn the socket into a listening socket if TCP
	ret = listen(sock, SOMAXCONN);
	if (ret == -1) {
		perror("listen");
		close(sock);
		exit(EXIT_FAILURE);
	}

	return sock;
}

int main(int argc, char* argv[]) {
	char* port = NULL;
	char* config_path = NULL;

	int verbose_flag = 0;
	port = DEFAULT_PORT;
	config_path = DEFAULT_CONFIG;

	int c;
	while ((c = getopt(argc, argv, "vp:c:")) != -1) {
		switch (c) {
			case 'v':
				verbose_flag = 1;
		 		break;
			case 'p':
				port = optarg;
				break;
			case 'c':
				config_path = optarg;
				break;
			case '?':
				if (optopt == 'p' || optopt == 'c') {
					fprintf(stderr, "Option -%c requires an argument\n", optopt);
					usage(argv[0]);
					exit(EXIT_FAILURE);
				}
			default:
				fprintf(stderr, "Unknown option encountered\n");
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	/* Instantiate your server class or call your server run function here */
	/* example: http_server_run(config_path, port, verbose_flag); */
	run_server(config_path, port, verbose_flag);

	return 0;
}

void usage(char* name) {
	printf("Usage: %s [-v] [-p port] [-c config-file]\n", name);
	printf("Example:\n");
        printf("\t%s -v -p 8080 -c http.conf \n", name);
	return;
}
