#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h> // fork

#include "include/server.h"

#include <sys/socket.h> // all socket and networking
#include <arpa/inet.h> // htonl, htons, inet_pton, inet_ntop
#include <netinet/in.h> // sockaddr, sockaddr_in

#include <string.h>

const char* default_ip = {"0.0.0.0"};
const char* default_root = {"./webroot"};

int main(int argc, char** argv) {
    char * ip_str = (char*)default_ip, * root = (char*) default_root;
    unsigned int ip;
    short port = htons(8080);
    for (int i = 1; i<argc; i++) {
        if (strcmp("-a", argv[i]) == 0) {
            if (i+1 > argc) {
                fprintf(stderr, "-a requires an argument!\n");
                exit(EXIT_FAILURE);
            } 
            ip_str = argv[++i];
            continue;
        }
        else if (strcmp("-p", argv[i]) == 0) {
            if (i+1 > argc) {
                fprintf(stderr, "-p requires an argument!\n");
                exit(EXIT_FAILURE);
            }
            if (sscanf(argv[++i], "%hu", &port) == EOF) {
                fprintf(stderr, "Invalid value `%s' for port argument!\n", argv[i+1]);
                exit(EXIT_FAILURE);
            }
            port = htons(port);
            continue;
        }
        else if (strcmp("-r", argv[i]) == 0) {
            if (i+1 > argc) {
                fprintf(stderr, "-r requires an argument!\n");
                exit(EXIT_FAILURE);
            }
            root = argv[++i];
            continue;
        }
        else {
            fprintf(stderr, "Warning! Unknown option `%s'!\n", argv[i]);
        }
    }

    if (inet_pton(AF_INET, ip_str, &ip) == 0) {
        fprintf(stderr, "Invalid IP address entered!\n");
        exit(EXIT_FAILURE);
    }

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Failed to create TCP socket! ");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr = {
        .sin_addr = ip,
        .sin_port = port,
        .sin_family = AF_INET,
        .sin_zero = {0}
    };

    if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Failed to bind to IP/port! ");
        exit(EXIT_FAILURE);
    }

    unsigned int addr_size = sizeof(struct sockaddr_in);

    int conn_fd = -1;

    char* ip_client = malloc(16); // max ipv4 text len
    assert(ip_client!=NULL);

    assert(listen(socket_fd, 32) != -1);

    printf("Running server on %s:%hu\n", ip_str, htons(port));

    while ((conn_fd = accept(socket_fd, (struct sockaddr *) &addr, &addr_size)) != -1) {
        switch (fork()) {
            case 0: // child
                server(conn_fd, addr);
                exit(EXIT_SUCCESS);
                break;
            default:
                inet_ntop(addr.sin_family, &addr.sin_addr, ip_client, 16);
                fprintf(stderr, "Recieved connection from %s:%d\n",ip_client, htons(addr.sin_port));
                close(conn_fd);
                break;
        }
    } 

    return 0;
}