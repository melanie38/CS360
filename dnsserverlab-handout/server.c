#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<errno.h>
#include<time.h>
#include<string.h>

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
	 char *etype = malloc(2);
	 char *erdata = malloc(512);

	 int index = 0;
	 cachedb_start = time(NULL);

	 while(fscanf(pfile, "%s %d %s %s %s", ename, &ttl, eclass, etype, erdata) == 5) {

		 char *name = malloc(32);
	 	 char *rdata = malloc(512);
		 char *type = malloc(2);

	 	 name = ename;
	 	 rdata = erdata;
		 type = etype;

		 // Converts rdata from string to bytes
	   inet_pton(AF_INET, rdata, rdata);
	 	 // Create the db entry
	 	 dns_rr rr;

	 	 rr.name = name;
		 rr.ttl = ttl; // use expires to invalidate entries that are too old
	 	 rr.class = 1;
	 	 rr.type = type; // make sure its 1 if type is A, 5 if type is CNAME
	 	 rr.rdata = rdata;

		 dns_db_entry entry;
	 	 entry.rr = rr;

	 	 // Insert entry in cache
	 	 cachedb[index] = entry;

	 	 index++;
		 //printf("%s %d %s\n", name, ttl, type);
		 //print_bytes(rdata, strlen(rdata));
	 }
/*
	 for(int i = 0; i < strlen(cachedb); i++) {
	 	printf("%s\n", cachedb[i].rr.name);
	 }
*/

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
}

dns_rr get_question(unsigned char *request) {
	/*
	 * Return a dns_rr for the question, including the query name and type.
	 *
	 * INPUT:  request: a pointer to the array of bytes representing the
	 *                  request received by the server.
	 * OUTPUT: a dns_rr structure for the question.
	 */
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
}

void serve_udp(unsigned short port) {
	/*
	 * Listen for and respond to DNS requests over UDP.
	 * Initialize the cache.  Initialize the socket.  Receive datagram
	 * requests over UDP, and return the appropriate responses to the
	 * client.
	 *
	 * INPUT:  port: a numerical port on which the server should listen.
	 */

	 init_db();
	 puts("cache is created");

	 struct sockaddr_in sock_server, sock_client;
	 char buf[BUFSIZ];

	 int sock = socket(AF_INET, SOCK_DGRAM, 0);

	 if (sock < 0) {
		 perror("Cannot create socket");
		 return 0;
	 }
	 puts("Socket created!");

	 memset((char*) &sock_server, 0, sizeof sock_server);
	 memset((char*) &sock_client, 0, sizeof sock_client);

	 sock_server.sin_family = AF_INET;
	 sock_server.sin_port = htons(53);
	 sock_server.sin_addr.s_addr = inet_addr("5888");

	 if (connect(sock, (struct sockaddr*) &sock_server, sizeof sock_server) < 0) {
		 perror("Connection failed");
		 exit(4);
	 }
	 puts("Connected!");

	 //send(sock, request, requestlen, 0);
	 //puts("Request sent:");
	 //print_bytes(request, requestlen);

	 //int reslen = recv(sock, response, 512, 0);
	 //puts("Answer recieved:");
	 //print_bytes(response, reslen);
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
	unsigned short port;
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
	port = atoi(argv[argindex]);

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
