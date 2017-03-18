#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<time.h>
//#define SIZEOF(x) (sizeof(x) / sizeof(*x))

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;


typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */
	
	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}

int name_ascii_to_wire(char *name, unsigned char *wire) {
	/* 
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp) {
	/* 
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only) {
	/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
}


int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
	/* 
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */

	// Header of the query

	srand((unsigned)time(NULL));

	wire[0] = rand() % 128;
	wire[1] = rand() % 128;;
	wire[2] = 0x00;
	wire[3] = 0x01;
	wire[5] = 0x01;
	//wire[12] = 0x03;

	// Question of the query
	
/*
	unsigned char *query;

	for (int i = 0; i < strlen(qname); i++) {
		query[i] = qname[i];
	}
*/
	int length = 12;
	for (char* p = strtok(qname, "."); p != NULL; p = strtok(NULL, ".")) {
		wire[length] = strlen(p);
		length++;
		memcpy(wire + length, p, strlen(p));
		length += strlen(p);
	}

	/*for(int i = 0; i < strlen(qname); i++) {
		wire[i + 13] = qname[i];
	}
	*/
	
	/*char end[] = {0x00, 0x00, 0x01, 0x00, 0x01};
	
	for(int i = 0; i < strlen(end); i++) {
		wire[i + strlen(qname) + 13] = end[i];
	}*/

	wire[length + 2] = 0x01;
	wire[length + 4] = 0x01;

	//print_bytes(wire, 33);
	//printf("%lu", sizeof(wire) / sizeof(wire[0]));
	//return SIZEOF(wire);
}

char *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a string representing the IP address in the answer; or NULL if none is found
	 */

	// for each resource record in the answer section
	// find owner name
	//int index = 12 + 18 + strlen(qname);
	
	int type = 0;
	char dest[INET_ADDRSTRLEN];
	int index = 18 + strlen(qname) + 3;
	int datalen = 0;
			
	while (1) {
		type = wire[index];
		printf("%d\n", type);

		if (type == 1) {
		//	puts("type = 1");
			char *src = wire + index + 9; //30 + strlen(qname);
			inet_ntop(AF_INET, src, dest, INET_ADDRSTRLEN);
			break;
		}
		else if (type == 5) {
		//	puts("type = 5");
			index += 8;
			index += wire[index];
			index += 4;
		}
		else {
			//dest[0] = 0;//printf("shouldn't be here");
			//break;
			return NULL;
		}
	}
/*
	type = wire[18 + strlen(qname) + 4];

			if (type == 1) {
				printf("type = 1");
				char *src = wire + 30 + strlen(qname);
				inet_ntop(AF_INET, src, dest, INET_ADDRSTRLEN);
				done = 1;
			}
*/	//int index = 120 - 11;
	//int compen = wire[index];
	
	
	char *result = dest;
	return result;
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port) {
	/* 
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */

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
	sock_server.sin_addr.s_addr = inet_addr(server);

	if (connect(sock, (struct sockaddr*) &sock_server, sizeof sock_server) < 0) {
		perror("Connection failed");
		exit(4);
	}
	puts("Connected!");
	
	send(sock, request, requestlen, 0);		
	//puts("Request sent:");
	//print_bytes(request, requestlen);

	int reslen = recv(sock, response, 512, 0);
	//puts("Answer recieved:");
	//print_bytes(response, reslen);
}

char *resolve(char *qname, char *server) {
	unsigned char wire[18 + strlen(qname)];
	unsigned char response[512];
	memset(wire, 0, sizeof wire);
	
	char tempq[strlen(qname)];
	char *c = tempq, *d = qname;
	while(*c++ = *d++);

	int length = sizeof wire / sizeof wire[0];

	//printf("%hu", create_dns_query(qname, 1, wire));
	create_dns_query(tempq, 1, wire);
	send_recv_message(wire, length, response, server, 53);
	char *result = get_answer_address(qname, 1, response);

	return result;
	/*
	char *ip = "still testing";
	return ip;
*/
}

int main(int argc, char *argv[]) {
	char *ip;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server>\n", argv[0]);
		exit(1);
	}
	ip = resolve(argv[1], argv[2]);
	printf("%s => %s\n", argv[1], ip == NULL ? "NONE" : ip);
}
