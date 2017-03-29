#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<errno.h>
#include<time.h>
#include<string.h>
#include <netdb.h>

#include "dns.h"

#define MAX_ENTRIES 1024
#define DNS_MSG_MAX 4096
// Set this to the maximum number of clients you want waiting to be serviced
#define LISTEN_QUEUE_SIZE	1024
#define BUFFER_MAX	1024

typedef struct {
	dns_rr rr;
	time_t expires;
} dns_db_entry;

dns_db_entry cachedb[MAX_ENTRIES];
time_t cachedb_start;
char *cachedb_file;

int create_server_socket(char* port, int protocol);

void init_db() {
	/*
	 * Import the cache database from the file specified by cachedb_file.
	 * Reset cachedb_start to the current time.  Zero the expiration
	 * for all unused cache entries to invalidate them.  Read each line in
	 * the file, create a dns_rr structure for each, set the expires time
	 * based on the current time and the TTL read from the file, and create
	 * an entry in the cachedb.  Zero the expiration for all unused cache
	 * entries to invalidate them.
	 *
	 * INPUT:  None
	 * OUTPUT: None
	 */

	FILE *pfile = fopen(cachedb_file,"r");

	char *ename = malloc(32);
	int ttl;
	char *eclass = malloc(2);
	char *etype = malloc(32);
	char *erdata = malloc(512);
	short type;// = malloc(2);

	int index = 0;

	// Set all entries of the db to 0
	for (int i = 0; i < MAX_ENTRIES; i++) {
		dns_db_entry init;
		init.expires = 0;
		init.rr.name = "none";

		cachedb[i] = init;
	}

	cachedb_start = time(NULL);

	while(fscanf(pfile, "%s %d %s %s %s", ename, &ttl, eclass, etype, erdata) == 5) {

	   	// Converts type to int
	   	if(strcmp(etype, "A") == 0) {
	   		type = 1;
	   		// Converts rdata from string to bytes
	   		inet_pton(AF_INET, erdata, erdata);
	   		cachedb[index].rr.rdata_len = 4; 	
	   	}
	   	else if(strcmp(etype, "CNAME") == 0) {
	   		type = 5;	   	
	   	}
	   	else if(strcmp(etype, "TXT") == 0) {
	   		type = 16;
	   		cachedb[index].rr.rdata_len = strlen(erdata); 	
	   	}

	   	//printf("the type will be %s\n", etype);

	 	// Insert entry in cache
	 	cachedb[index].rr.name = ename;
	 	//cachedb[index].rr.ttl = ttl;
	 	cachedb[index].rr.class = 1;
	 	cachedb[index].rr.type = type;
	 	cachedb[index].rr.rdata = erdata;
	 	cachedb[index].expires = cachedb_start + ttl;

	 	//printf("%s %u\n", cachedb[index].rr.name, cachedb[index].rr.type);

	 	index++;
		//print_bytes(cachedb[index].rr.rdata, 1024);
		ename = malloc(32);
	 	erdata = malloc(512);
		etype = malloc(32);
		//type = malloc(2);

		//printf("%s %d\n", cachedb[index].rr.name, cachedb[index].rr.type);
	}
/*
	for(int i = 0; i < 5; i++) {
	 	printf("%s %u\n", cachedb[i].rr.name, cachedb[i].rr.rdata_len);
	}
*/
}
int search_db(dns_rr request) {

	for (int i = 0; i < MAX_ENTRIES; i++) {
		if (strcmp(cachedb[i].rr.name, request.name) == 0) {
			if (cachedb[i].expires - time(NULL) > 0) {
				if(cachedb[i].rr.type == request.type) {
					//printf("a match is found!\n");
					return i;
				}
			}
		}
		//printf("name: %s\n", cachedb[i].rr.name);
		//printf("type: %d\n", cachedb[i].rr.type);
	}
	//printf("no match found in db\n");
	return -1;
}
int is_valid_request(unsigned char *request) {
	/*
	 * Check that the request received is a valid query.
	 *
	 * INPUT:  request: a pointer to the array of bytes representing the
	 *                  request received by the server
	 * OUTPUT: a boolean value (1 or 0) which indicates whether the request
	 *                  is valid.  0 should be returned if the QR flag is
	 *                  set (1), if the opcode is non-zero (not a standard
	 *                  query), or if there are no questions in the query
	 *                  (question count != 1).
	 */
	
	//print_bytes(request, req_length);
	
	int QR_flag_opcode;
	int question;
	
	QR_flag_opcode = request[2];
	question = request[5];
	
	//printf("%d\n", QR_flag_opcode);
	//printf("%d\n", question);
	
	if(QR_flag_opcode > 4095 || question != 1) {
		return 0;
	}
	
	return 1;
}

dns_rr get_question(unsigned char *request) {
	/*
	 * Return a dns_rr for the question, including the query name and type.
	 *
	 * INPUT:  request: a pointer to the array of bytes representing the
	 *                  request received by the server.
	 * OUTPUT: a dns_rr structure for the question.
	 */

	dns_rr rr;

	int i = 12;
	int j = request[12];
	int l = 0;
	int name_length = strlen(request + 13);
	
	//printf("%d\n", name_length);
	
	char temp[name_length + 1];
	//printf("%s\n", temp);

	while(request[i] != 0) {
		i++;
		for (int k = 0; k < j; k++) {
			temp[l] = request[i];
			i++;
			l++;
			//printf("%s\n", temp);
		}
		
		j = request[i];
		if (j != 0) {
			temp[l] = '.';
			l++;
			//printf("%s\n", temp);
		}
	}

	temp[l] = '\0';
	//printf("%s\n", temp);

	rr.name = temp;
	rr.type = request[i + 2];
	rr.class = request[i + 4];

	//printf("%s\n", rr.name);
	//printf("%d\n", rr.type);
	//printf("%d\n", rr.class);
	
	return rr;
}

int get_response(unsigned char *request, int len, unsigned char *response) {
	/*
	 * Handle a request and produce the appropriate response.
	 *
	 * Start building the response:
	 *   copy ID from request to response;
	 *   clear all flags and codes;
	 *   set QR bit to 1;
	 *   copy RD flag from request;
	 *
	 * If the request is not valid:
	 *   set the response code to 1 (FORMERR).
	 *   set all section counts to 0
	 *   return 12 (length of the header only)
	 *
	 * Otherwise:
	 *
	 *   Continue building the response:
	 *     set question count to 1;
	 *     set authority and additional counts to 0
	 *     copy question section from request;
	 *
	 *   Search through the cache database for an entry with a matching
	 *   name and type which has not expired
	 *   (expiration - current time > 0).
	 *
	 *     If no match is found:
	 *       the answer count will be 0, the response code will
	 *       be 3 (NXDOMAIN or name does not exist).
	 *
	 *     Otherwise (a match is found):
	 *       the answer count will be 1 (positive), the response code will
	 *       be 0 (NOERROR), and the appropriate RR will be added to the
	 *       answer section.  The TTL for the RR in the answer section
	 *       should be updated to expiration - current time.
	 *
	 *   Return the length of the response message.
	 *
	 * INPUT:  request: a pointer to the array of bytes representing the
	 *                  request received by the server.
	 * INPUT:  len: the length (number of bytes) of the request
	 * INPUT:  response: a pointer to the array of bytes where the response
	 *                  message should be constructed.
	 * OUTPUT: the length of the response message.
	 */

	int valid = is_valid_request(request);

/*	if(valid) {
		printf("request is valid\n");
	}
	else {
		printf("request is not valid\n");
	}
*/
	// copy ID from request to response
	response[0] = request[0];
	response[1] = request[1];
	// clear all flags and codes
	// set QR code to 1, RD flag similar to request
	response[2] = 0x81; //request[2];

	if(!valid) {
		// set response code to 1 (FORMERR)
		response[3] = 0x01;
		// set all section counts to 0
		int i = 4;
		while(i < 12) {
			response[i] = 0x00;
			i++;
		}
		// return the length of the header (12)
		return i;
	}

	// set Rcode to 0
	response[3] = 0x00;
	// set Total Questions to 1
	response[4] = 0x00;
	response[5] = 0x01;
	// set Authority RR's and Additional RR's to 0
	int i = 8;
	while(i < 12) {
		response[i] = 0x00;
		i++;
	}
	// copy question section from request
	while(request[i] != 0) {
		response[i] = request[i];
		i++;
	}

	// set the last bit of the name to 0 (end of string)
	response[i] = 0x00;
	i++;

	int index = search_db(get_question(request));
	dns_rr rr = cachedb[index].rr;
	time_t expires = cachedb[index].expires;

	// if no entry in the database match the name and type or is expired
	if(index == -1) {
		// set the response code to 3 (NXDOMAIN)
		response[3] = 0x03;
		// set the answer count to 0
		response[7] = 0x00;
		//print_bytes(response, i);
		return i;
	}
	else {
		// set the answer count to 1
		response[7] = 0x01;
		// set type of request
		for(int j = 0; j < 4; j++) {
			response[i] = request[i];
			i++;
		}
		// set class of request

		// set name
		response[i] = 0xc0;
		i++;
		response[i] = 0x0c;
		i++;
		// set type
		response[i] = 0x00;
		i++;
		response[i] = rr.type;
		i++;
		// set class
		response[i] = 0x00;
		i++;
		response[i] = rr.class;
		i++;
		// set ttl (4 bytes)
		response[i] = 0x00;
		i++;
		response[i] = 0x00;
		i++;
		response[i] = 0x00;
		i++;
		response[i] = expires - time(NULL);
		i++;
		// rr.ttl = ((expires - time(NULL))) | 0x00000000;
  		// memcpy(response + i, &rr.ttl, sizeof(rr.ttl));
  		// i += sizeof(rr.ttl);

		// set rdata_len (2 bytes)
		response[i] = 0x00;
		i++;
		memcpy(response + i, &rr.rdata_len, 2);
		i++;
		// add appropriate RR
		memcpy(response + i, &rr.rdata, rr.rdata_len);
	}

	//print_bytes(cachedb[index].rr.rdata, cachedb[index].rr.rdata_len);
	//print_bytes(request, len);
	print_bytes(response, i + rr.rdata_len);

	return i + rr.rdata_len;
}

void serve_udp(char* port) {
	/*
	 * Listen for and respond to DNS requests over UDP.
	 * Initialize the cache.  Initialize the socket.  Receive datagram
	 * requests over UDP, and return the appropriate responses to the
	 * client.
	 *
	 * INPUT:  port: a numerical port on which the server should listen.
	 */

	init_db();
	//puts("cache is created");

	int sock = create_server_socket(port, SOCK_DGRAM);
	char message[BUFFER_MAX];
	char client_hostname[NI_MAXHOST];
	char client_port[NI_MAXSERV];
	
	printf("Listening on UDP port %s\n", port);
	
	while (1) {
		struct sockaddr_storage client_addr;
		int msg_length;
		socklen_t client_addr_len = sizeof(client_addr);
		
		// Receive a message from a client
		if ((msg_length = recvfrom(sock, message, BUFFER_MAX, 0, (struct sockaddr*)&client_addr, &client_addr_len)) < 0) {
			fprintf(stderr, "Failed in recvfrom\n");
			continue;
		}
		
		//is_valid_request(message, msg_length);
		char response[BUFFER_MAX];
		int res_len = get_response(message, msg_length, response);

		// Get and print the address of the peer (for fun)
		int ret = getnameinfo((struct sockaddr*)&client_addr, client_addr_len,
							  client_hostname, BUFFER_MAX, client_port, BUFFER_MAX, 0);
		if (ret != 0) {
			fprintf(stderr, "Failed in getnameinfo: %s\n", gai_strerror(ret));
		}
		printf("Got a message from %s:%s\n", client_hostname, client_port);
		
		// Just echo the message back to the client
		//sendto(sock, message, msg_length, 0, (struct sockaddr*)&client_addr, client_addr_len);
		sendto(sock, response, res_len, 0, (struct sockaddr*)&client_addr, client_addr_len);
	}
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
	ret = listen(sock, LISTEN_QUEUE_SIZE);
	if (ret == -1) {
		perror("listen");
		close(sock);
		exit(EXIT_FAILURE);
	}
	
	return sock;
}

void serve_tcp(unsigned short port) {
	/*
	 * Listen for and respond to DNS requests over TCP.
	 * Initialize the cache.  Initialize the socket.  Receive requests
	 * requests over TCP, ensuring that the entire request is received, and
	 * return the appropriate responses to the client, ensuring that the
	 * entire response is transmitted.
	 *
	 * Note that for requests, the first two bytes (a 16-bit (unsigned
	 * short) integer in network byte order) read indicate the size (bytes)
	 * of the DNS request.  The actual request doesn't start until after
	 * those two bytes.  For the responses, you will need to similarly send
	 * the size in two bytes before sending the actual DNS response.
	 *
	 * In both cases you will want to loop until you have sent or received
	 * the entire message.
	 *
	 * INPUT:  port: a numerical port on which the server should listen.
	 */
}

int main(int argc, char *argv[]) {
	//unsigned short port;
	char* port = malloc(16);
	int argindex = 1, daemonize = 0;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-d] <cache file> <port>\n", argv[0]);
		exit(1);
	}
	if (argc > 3) {
	       	if (strcmp(argv[1], "-d") != 0) {
			fprintf(stderr, "Usage: %s [-d] <cache file> <port>\n", argv[0]);
			exit(1);
		}
		argindex++;
		daemonize = 1;
	}
	cachedb_file = argv[argindex++];
	//port = atoi(argv[argindex]);
	port = argv[argindex];

	// daemonize, if specified, and start server(s)
	// ...

	if(daemonize) {
		pid_t pid = fork();
		if (pid != 0) {
			exit(0);
		}
	}
	serve_udp(port);
}
