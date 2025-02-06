#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h> // sockaddr_in
#include <sys/socket.h> // recv, setsockopt

#include <string.h> // memset, strncmp

#include <errno.h>

#include <unistd.h> // close

#define MAX_TIMEOUT 3

#define MAX_REQUEST_SIZE (1024*1024) // 1 MB

static inline void respond(char * buffer, int socket_fd);

void server(int socket_fd, struct sockaddr_in addr) {

    struct timeval time = {
        .tv_sec = MAX_TIMEOUT,
        .tv_usec = 0
    };
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(struct timeval)) == -1) {
        perror("Failed to set recieve timeout ");
    }

    char * buffer = malloc(MAX_REQUEST_SIZE);
    assert(buffer != NULL);

    int recv_amount;

    while (1) {
        memset(buffer, 0, MAX_REQUEST_SIZE);
        switch (recv_amount = recv(socket_fd, buffer, MAX_REQUEST_SIZE, MSG_TRUNC)) {
            case -1:
                if (errno == ETIMEDOUT || errno == EAGAIN) { // syscall specifies EAGAIN, programmer manual ETIMEDOUT, EAGAIN works  ???
                    fprintf(stderr, "Timeout reached while waiting for client; ending connection...\n");
                    shutdown(socket_fd, SHUT_RDWR);
                    close(socket_fd);
                    exit(EXIT_FAILURE);
                }
                if (errno == ECONNRESET || errno == ENOTCONN) {
                    END:
                    fprintf(stderr, "Connection closed by client...\n");
                    close(socket_fd);
                    exit(EXIT_FAILURE);
                }
                perror("WARNING: Ran into an error while running recv(): ");
                break;
            case 0:
                goto END;
                break;
            default:
                if (recv_amount > MAX_REQUEST_SIZE) { // works because MSG_TRUNC
                    fprintf(stderr, "WARNING: Recieved request too large (%d/%d)!\n", recv_amount, MAX_REQUEST_SIZE);
                }
                respond(buffer, socket_fd);
                break;
        }
    }

    return;
}

static inline void respond(char * buffer, int socket_fd) {
    // parse request type
}