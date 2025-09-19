#ifndef SERVER_H
#define SERVER_H
#include <netinet/in.h>

//#define MAX_REQUEST_SIZE (1500-14-20-32) // Default MTU - ethernet II - ipv4 - tcp header
#define MAX_REQUEST_SIZE (1<<14) // TLS record size, so might as well
#define free(a) {free(a); a = NULL;} // prevents UAF

void server(int socket_fd);
char ssl_wrapper(int socket_fd); // tls_wrapper.c

#endif