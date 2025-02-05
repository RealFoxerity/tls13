#ifndef SERVER_H
#define SERVER_H
#include <netinet/in.h>

void server(int socket_fd, struct sockaddr_in addr);

#endif