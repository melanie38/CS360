/* 
 * Melanie Lambson <mlalahar>
 * CS360 - Section 1
 * Homework#6
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

pid_t pid;
void die(int signum);
void new(int signum);
struct sigaction sigact;

void start() {

	int status;
	char str[BUFSIZ];
	char *my_args[3];

	puts("Please enter the path to a text file to read");
	scanf("%s", str);

	if(!strcmp("q", str)) {
		exit(EXIT_SUCCESS);
	}

	my_args[0] = "reader";
	my_args[2] = NULL;
	my_args[1] = str;
	
	switch ((pid = fork())) {

		case -1:
			perror ("fork");
			break;
		case 0:
			execv("reader", my_args);
			puts("execv() must have failed");
			exit(EXIT_FAILURE);
			break;
		default:
			
			memset(&sigact, 0, sizeof(sigact));
			
			while (waitpid(pid, &status, WNOHANG) == 0) {
				switch (getchar()) {
					case 's':
						kill(pid, SIGTERM);
						sigact.sa_handler = die;			
						sigaction(SIGTERM, &sigact, NULL);
						waitpid(-1, &status, 0);
						break;
					case 'p':
						kill(pid, SIGSTOP);
						break;
					case 'r':
						kill(pid, SIGCONT);
						break;
					case '+':
						kill(pid, SIGUSR1);
						break;
					case '-':
						kill(pid, SIGUSR2);
						break;
					case 'q':
						kill(pid, SIGINT);
						sigact.sa_handler = die;
						sigaction(SIGINT, &sigact, NULL);
						waitpid(-1, &status, 0);
						exit(EXIT_SUCCESS);
						break;
					default:
						break;
				}
			}

			break;
	}

	start();
}

void die(int signum) {
	if(signum == SIGINT) {
		if(pid > 0) {
			kill(pid, SIGKILL);
		}
	}
}

int main(void) {

	printf("Welcome to the speed reader controller!\n");
	printf("Use the following hot keys to control your experience\n");
	printf("		[s]tart new book\n");
	printf("		[p]ause playback\n");
	printf("		[r]esume playback\n");
	printf("		[+] speed up\n");
	printf("		[-] slow down\n");
	printf("		[q]uit\n");

	start();
	
	puts("End of program");
	return 0;
}

