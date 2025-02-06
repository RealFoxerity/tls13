#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h> // sockaddr_in
#include <sys/socket.h> // recv, setsockopt

#include <string.h> // memset, strncmp

#include <errno.h>

#include <unistd.h> // close

#include "include/http_status_codes.h"

#define MAX_TIMEOUT 3

#define MAX_REQUEST_SIZE (1024*1024) // 1 MB

static inline void respond(char * buffer, int socket_fd);

#define max(a,b) (a>b?a:b)

extern const int true;

extern char * real_root;

void server(int socket_fd, struct sockaddr_in addr) {
    struct timeval time = {
        .tv_sec = MAX_TIMEOUT,
        .tv_usec = 0
    };
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(struct timeval)) == -1) {
        perror("Failed to set recieve timeout ");
    }

    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int));

    char * buffer = malloc(MAX_REQUEST_SIZE);
    assert(buffer != NULL);

    int recv_amount;

    errno = 0;

    while (1) {
        memset(buffer, 0, MAX_REQUEST_SIZE);

        recv_amount = recv(socket_fd, buffer, MAX_REQUEST_SIZE, 0);

        switch (recv_amount) {
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
                if (recv_amount == MAX_REQUEST_SIZE) { 
                    fprintf(stderr, "WARNING: Reached maximum request size, won't read further! %d!\n", MAX_REQUEST_SIZE);
                }
                respond(buffer, socket_fd);
                break;
        }
    }

    return;
}

static inline void respond_not_implemented(int socket_fd) {
    char * not_implemented = malloc(256);
    assert(not_implemented != NULL);
    memset(not_implemented, 0, 256);

    sprintf(not_implemented, "HTTP/1.1 %d Not Implemented\r\n\r\n", HTTP_NOT_IMPLEMENTED);
    send(socket_fd, not_implemented, strlen(not_implemented), 0);
    free(not_implemented);
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    exit(EXIT_SUCCESS);
}

static inline void respond_bad_request(int socket_fd) {
    printf("Recieved malformed request\n");
    char * bad_request = malloc(256);
    assert(bad_request != NULL);
    memset(bad_request, 0, 256);

    sprintf(bad_request, "HTTP/1.1 %d Bad Request\r\n\r\n", HTTP_BAD_REQUEST);
    send(socket_fd, bad_request, strlen(bad_request), 0);
    free(bad_request);
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    exit(EXIT_SUCCESS);
}

static inline void respond_not_found(int socket_fd) {
    char * not_found = malloc(256);
    assert(not_found != NULL);
    memset(not_found, 0, 256);

    sprintf(not_found, "HTTP/1.1 %d Not Found\r\n\r\n", HTTP_NOT_FOUND);
    send(socket_fd, not_found, strlen(not_found), 0);
    free(not_found);
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    exit(EXIT_SUCCESS);
}

static inline void respond_not_found_OOB_warn(int socket_fd, char * path) {
    fprintf(stderr, "WARNING: Tried to read outside of webroot: %s\n", path);
    respond_not_found(socket_fd);
}


static inline void respond_unathorized(int socket_fd) {
    printf("GET Path outside of root\n");
    char * unauthorized = malloc(256);
    assert(unauthorized != NULL);
    memset(unauthorized, 0, 256);

    sprintf(unauthorized, "HTTP/1.1 %d Unauthorized\r\n\r\n", HTTP_UNAUTHORIZED);
    send(socket_fd, unauthorized, strlen(unauthorized), 0);
    free(unauthorized);
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    exit(EXIT_SUCCESS);
}


static inline void respond_get_request(int socket_fd, char* buffer) {
    int path_len = strchrnul(buffer, '\n') - strchr(buffer, ' ');

    char * line = malloc(path_len);
    char * http_version = malloc(path_len);
    char * requested_path = malloc(PATH_MAX+strlen(real_root)+1);
    char * path = malloc(PATH_MAX);

    assert(line != NULL);
    assert(http_version != NULL);
    assert(requested_path != NULL);
    assert(path != NULL);

    memset(line, 0, path_len);
    memset(http_version, 0, path_len);
    memset(requested_path, 0, PATH_MAX+strlen(real_root)+1);
    memset(path, 0, PATH_MAX);

    strcpy(requested_path, real_root);
    requested_path[strlen(real_root)] = '/';

    char * out = malloc(MAX_REQUEST_SIZE);
    assert(out != NULL);

    if (strncmp(buffer, "HEAD ", 4) == 0) {
        if (sscanf(buffer, "HEAD %s %s\r\n", line, http_version) != 2 || strncmp(http_version, "HTTP/1.1", max(strlen(http_version), 8)) != 0) respond_bad_request(socket_fd); 
    } else {
        if (sscanf(buffer, "GET %s %s\r\n", line, http_version) != 2 || strncmp(http_version, "HTTP/1.1", max(strlen(http_version), 8)) != 0) respond_bad_request(socket_fd);
    }
    
    char * get_parameters = strchr(line, '?');
    if (get_parameters != NULL) *get_parameters = '\0';

    strcpy(requested_path+strlen(real_root)+1, line);

    if (realpath(requested_path, path) == NULL) respond_not_found(socket_fd);

    if (strncmp(real_root, path, strlen(real_root)) != 0) respond_not_found_OOB_warn(socket_fd, path); // respond_unathorized(socket_fd);

}

static inline void respond(char * buffer, int socket_fd) {
    // parse request type
    if (strncmp(buffer, "GET ", 4) == 0 || strncmp(buffer, "HEAD ", 5) == 0) {
        respond_get_request(socket_fd, buffer);
//    } else if (strncmp (buffer, "POST ", 5) == 0) {
//        
//    } else if (strncmp(buffer, "PUT ", 4) == 0) {
//
    } else {
        fprintf(stderr, "Recieved an invalid request!\n");
        respond_not_implemented(socket_fd);
    }
}