#
# Student makefile for webserver lab
# Note: requires a 64-bit x86-64 system 
#
CC = gcc
CFLAGS = -g

all: server

server: server.c
	$(CC) $(CFLAGS) -o server server.c -lm 

clean:
	rm -f server