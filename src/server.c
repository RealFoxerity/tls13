#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h> // sockaddr_in
#include <sys/socket.h> // recv, setsockopt
#include <sys/stat.h> // stat

#include <string.h> // memset, strncmp

#include <errno.h>

#include <unistd.h> // close, access

#include "include/http_status_codes.h"
#include "include/mime_types.h"

#define MAX_TIMEOUT 3

#define MAX_REQUEST_SIZE (25*1024*1024) // 25 MB

char * buffer = NULL, * out = NULL, * path = NULL;

#define free(a) {free(a); a = NULL;}
#define exit(a) {free(real_root); free(buffer); free(out); free(path); exit(a);}


static inline void respond(char * buffer, int socket_fd);

#define max(a,b) (a>b?a:b)

extern const int true;

extern char * real_root;

extern char ip_client[16];
extern struct sockaddr_in addr;

void server(int socket_fd, struct sockaddr_in addr) {
    struct timeval time = {
        .tv_sec = MAX_TIMEOUT,
        .tv_usec = 0
    };
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(struct timeval)) == -1) {
        perror("Failed to set recieve timeout ");
    }

    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int));

    buffer = malloc(MAX_REQUEST_SIZE);
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

#define SERVER_NAME "skibittp"

static inline void respond_not_implemented(int socket_fd) {
    fprintf(stderr, "501 Not Implemented\n");
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
    fprintf(stderr, "400 Recieved malformed request\n");
    char * bad_request = malloc(256);
    assert(bad_request != NULL);
    memset(bad_request, 0, 256);

    sprintf(bad_request, "HTTP/1.1 %d Bad Request\r\n\
Server: %s\r\n\
Content-Type: text/plain\r\n\
Content-Length: 11\r\n\
\r\n\
Bad Request", HTTP_BAD_REQUEST, SERVER_NAME);
    send(socket_fd, bad_request, strlen(bad_request), 0);
    free(bad_request);
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    exit(EXIT_SUCCESS);
}

static inline void respond_not_found(int socket_fd) {
    fprintf(stderr, "404 Not Found\n");
    char * not_found = malloc(256);
    assert(not_found != NULL);
    memset(not_found, 0, 256);

    sprintf(not_found, "HTTP/1.1 %d Not Found\r\n\
Server: %s\r\n\
Content-Type: text/plain\r\n\
Content-Length: 9\r\n\
\r\n\
Not Found", HTTP_NOT_FOUND, SERVER_NAME);
    send(socket_fd, not_found, strlen(not_found), 0);
    free(not_found);
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    exit(EXIT_SUCCESS);
}

static inline void respond_not_found_OOB_warn(int socket_fd) {
    fprintf(stderr, "outside of webroot ");
    respond_not_found(socket_fd);
}


static inline void respond_forbidden(int socket_fd) {
    fprintf(stderr, "403 Forbidden\n");
    char * forbidden = malloc(256);
    assert(forbidden != NULL);
    memset(forbidden, 0, 256);

    sprintf(forbidden, "HTTP/1.1 %d Forbidden\r\n\
Server: %s\r\n\
Content-Type: text/plain\r\n\
Content-Length: 9\r\n\
\r\n\
Forbidden", HTTP_FORBIDDEN, SERVER_NAME);
    send(socket_fd, forbidden, strlen(forbidden), 0);
    free(forbidden);
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    exit(EXIT_SUCCESS);
}

static inline void respond_content_too_large(int socket_fd) {
    fprintf(stderr, "413 Requested/uploaded resource too large\n");
    char * ct_large = malloc(256);
    assert(ct_large != NULL);
    memset(ct_large, 0, 256);

    sprintf(ct_large, "HTTP/1.1 %d Content Too Large\r\n\
Server: %s\r\n\
Content-Type: text/plain\r\n\
Content-Length: 17\r\n\
\r\n\
Content too large", HTTP_CONTENT_TOO_LARGE, SERVER_NAME);
    send(socket_fd, ct_large, strlen(ct_large), 0);
    free(ct_large);
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    exit(EXIT_SUCCESS);
}

static inline void respond_get_request(int socket_fd, char* buffer) {
    int path_len = strchrnul(buffer, '\n') - strchr(buffer, ' ');

    char * line = malloc(path_len);
    char * http_version = malloc(path_len);
    char * requested_path = malloc(PATH_MAX+strlen(real_root)+1);
    path = malloc(PATH_MAX);

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

    char is_head = 0;

    if (strncmp(buffer, "HEAD ", 5) == 0) {
        is_head = 1;
        if (sscanf(buffer, "HEAD %s %s\r\n", line, http_version) != 2 || strncmp(http_version, "HTTP/1.1", max(strlen(http_version), 8)) != 0) respond_bad_request(socket_fd); 
    } else {
        if (sscanf(buffer, "GET %s %s\r\n", line, http_version) != 2 || strncmp(http_version, "HTTP/1.1", max(strlen(http_version), 8)) != 0) respond_bad_request(socket_fd);
    }
    
    char * get_parameters = strchr(line, '?');
    if (get_parameters != NULL) *get_parameters = '\0';

    if (strncmp(line, "/", max(strlen(line), 1)) == 0) strcpy(line, "/index.html");
    
    strcpy(requested_path+strlen(real_root)+1, line);

    fprintf(stderr, "[%s:%d] %s %s -> ", ip_client, htons(addr.sin_port), is_head?"HEAD":"GET", requested_path);

    free(line);
    free(http_version);

    if (realpath(requested_path, path) == NULL) {
        free(requested_path);
        respond_not_found(socket_fd);
    }
    free(requested_path);

    if (strncmp(real_root, path, strlen(real_root)) != 0) respond_not_found_OOB_warn(socket_fd); // respond_unathorized(socket_fd);

    if (access(path, F_OK) != 0) respond_not_found(socket_fd);
    if (access(path, R_OK) != 0) respond_forbidden(socket_fd);

    struct stat file_stat;
    stat(path, &file_stat);

    if (S_ISDIR(file_stat.st_mode)) respond_forbidden(socket_fd);

    out = malloc(MAX_REQUEST_SIZE);
    assert(out != NULL);
    memset(out, 0, MAX_REQUEST_SIZE);

    int header_size;
    size_t file_len;
    if (!is_head) {
        FILE * file_fd = fopen(path, "r");
        assert(file_fd != NULL); // handled by access(..., R_OK);

        fseek(file_fd, 0, SEEK_END);

        file_len = ftell(file_fd);
        rewind(file_fd);

        sprintf(out, "HTTP/1.1 %d OK\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\n\r\n", HTTP_OK, SERVER_NAME, identify_mime_type(path), file_len);

        header_size = strlen(out);

        if (file_len + header_size > MAX_REQUEST_SIZE) {fclose(file_fd); respond_content_too_large(socket_fd);}

        fread(out+header_size, 1, file_len, file_fd);
        free(path);
        fclose(file_fd);
    } else {
        sprintf(out, "HTTP/1.1 %d OK\r\nServer: %s\r\nContent-Type: %s\r\n\r\n", HTTP_OK, SERVER_NAME, identify_mime_type(path));
        header_size = strlen(out);
        file_len = 0;
    }
    fprintf(stderr, "200\n");

    send(socket_fd, out, header_size+file_len, 0);

    close(socket_fd);
    free(out);

    exit(EXIT_SUCCESS);

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