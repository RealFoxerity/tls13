#include <linux/limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h> // fork

#include "include/server.h"

#include <sys/socket.h> // all socket and networking
#include <arpa/inet.h> // htonl, htons, inet_pton, inet_ntop
#include <netinet/in.h> // sockaddr, sockaddr_in

#include <string.h>

#include <sys/wait.h>

#define MAX_CLIENTS 15

const char* default_ip = {"0.0.0.0"};
const char* default_root = {"./webroot"};

int child_count = 0;

const int true = 1;

void child_callback() {
    fprintf(stderr, "Server thread terminated\n");
    child_count --;
    wait(NULL); // so that the child does not turn into a zombie
    return;
}

#define naive_max_input 256

int socket_fd;

char * root = NULL;
char * real_root = NULL;
char * ip_str = NULL;

char ip_client[16] = {0}; // max ipv4 text len
struct sockaddr_in addr = {0};

void terminate() {
    fprintf(stderr, "Recieved SIGINT, exiting...\n");
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    while(wait(NULL) != -1); // wait for all child processes

    free(real_root);
    
    exit(EXIT_SUCCESS);
}

pid_t server_pid;


int main(int argc, char** argv) {
    ip_str = (char*)default_ip;
    root = (char*) default_root;
    unsigned int ip;
    short port = htons(8080);

    server_pid = getpid();

    signal(SIGCHLD, child_callback);
    signal(SIGINT, terminate);

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

    real_root = malloc(PATH_MAX);
    assert(real_root != NULL);

    memset(real_root, 0, PATH_MAX);

    realpath(root, real_root);

    if (inet_pton(AF_INET, ip_str, &ip) == 0) {
        fprintf(stderr, "Invalid IP address entered!\n");
        exit(EXIT_FAILURE);
    }

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Failed to create TCP socket! ");
        exit(EXIT_FAILURE);
    }

    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int));

    addr = (struct sockaddr_in){
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
    
    assert(listen(socket_fd, 32) != -1);

    printf("Running server on %s:%hu\n", ip_str, htons(port));

    while ((conn_fd = accept(socket_fd, (struct sockaddr *) &addr, &addr_size)) != -1) {
        if (child_count > MAX_CLIENTS) {
            fprintf(stderr, "WARNING: Maximum client count reached, refusing new connection...\n");
            shutdown(conn_fd, SHUT_RDWR);
            close(conn_fd);
        }
        
        child_count ++;
        inet_ntop(addr.sin_family, &addr.sin_addr, ip_client, 16);
        fprintf(stderr, "Recieved connection from %s:%d\n",ip_client, htons(addr.sin_port));

        switch (fork()) {
            case 0: // child
                server(conn_fd, addr);
                exit(EXIT_SUCCESS);
                break;
            default:
                close(conn_fd);
                break;
        }
    } 

    return 0;
}