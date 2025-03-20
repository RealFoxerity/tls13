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
#include <sys/select.h>

#include <string.h>

#include <sys/wait.h>

#include <time.h>

#include <errno.h>

#define MAX_CLIENTS 15
#define DEFAULT_PORT 80
#define DEFAULT_PORT_HTTPS 443

#define MAX_LEN_DOMAIN 256

#define MIN(a,b) (a>b?b:a)
#define MAX(a,b) (a<b?b:a)

const char* default_ip = {"0.0.0.0"};
const char* default_root = {"./webroot"};
const char* default_domain = "*";
int child_count = 0;

const int true = 1;

void child_callback() {
    fprintf(stderr, "Server thread terminated\n");
    child_count --;
    wait(NULL); // so that the child does not turn into a zombie
    return;
}

#define naive_max_input 256

int socket_fd, socket_fd_ssl;

char * root = NULL;
char * real_root = NULL;
char * ip_str = NULL;
char * domain = NULL;

char ip_client[16] = {0}; // max ipv4 text len
struct sockaddr_in addr = {0}, addr_ssl = {0};

void terminate() {
    fprintf(stderr, "Recieved SIGINT, exiting...\n");
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    while(wait(NULL) != -1)
    ; // wait for all child processes

    free(real_root);
    
    exit(EXIT_SUCCESS);
}

pid_t server_pid;

char * ssl_priv_key = NULL;
char * ssl_cert = NULL;

char ssl = 0;


int main(int argc, char** argv) {
    if (geteuid() == 0) fprintf(stderr, "WARNING: RUNNING AS ROOT\nSET CAP_NET_BIND_SERVICE IF YOU NEED PORT < 1024!\n");

    ip_str = (char*)default_ip;
    root = (char*) default_root;
    domain = (char*) default_domain;

    unsigned int ip;
    unsigned short port = htons(DEFAULT_PORT);
    unsigned short ssl_port = htons(DEFAULT_PORT_HTTPS);

    server_pid = getpid();

    signal(SIGCHLD, child_callback);
    signal(SIGINT, terminate);

    for (int i = 1; i<argc; i++) {
        if (strcmp("--help", argv[i]) == 0 || strcmp("-h", argv[i]) == 0) {
            help:
            fprintf(stderr, 
"Usage:\n"
"%s [-p port] [-a addr] [-r webroot] [-d domain] (-s -c chain.pem -k privkey.key [-o port2])\n"
"-p\t\tPort for http (default 80)\n"
"-a\t\tAddress to bind to (default 0.0.0.0)\n"
"-r\t\tRoot of server (default ./webroot/)\n"
// "-d\t\tDomain to handle requests for (* for all) (default *) (anything else will be dropped)\n" // doesn't make sense
"-s\t\tAlso use HTTP over TLS (HTTPS) (default do not)\n"
"-c\t\tSSL certificate path\n"
"-k\t\tSSL private key path\n"
"-o\t\tHTTPS port (default 443)\n"
, argv[0]
);
exit(EXIT_SUCCESS);
        }
        else if (strcmp("-a", argv[i]) == 0) {
            if (i+1 >= argc) {
                fprintf(stderr, "-a requires an argument!\n");
                exit(EXIT_FAILURE);
            } 
            ip_str = argv[++i];
            continue;
        }
        else if (strcmp("-p", argv[i]) == 0) {
            if (i+1 >= argc) {
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
            if (i+1 >= argc) {
                fprintf(stderr, "-r requires an argument!\n");
                exit(EXIT_FAILURE);
            }
            root = argv[++i];
            continue;
        } else if (strcmp("-s", argv[i]) == 0) {
            ssl = 1;
            continue;
        } else if (strcmp("-c", argv[i]) == 0) {
            if (i+1 >= argc) {
                fprintf(stderr, "-c requires an argument!\n");
                exit(EXIT_FAILURE);
            }
            ssl_cert = argv[++i];
            continue;
        }else if (strcmp("-k", argv[i]) == 0) {
            if (i+1 >= argc) {
                fprintf(stderr, "-k requires an argument!\n");
                exit(EXIT_FAILURE);
            }
            ssl_priv_key = argv[++i];
            continue;
        }
        else if (strcmp("-d", argv[i]) == 0) {
            if (i+1 >= argc) {
                fprintf(stderr, "-d requires an argument!\n");
                exit(EXIT_FAILURE);
            }
            domain = argv[++i];
            continue;
        }
        else if (strcmp("-o", argv[i]) == 0) {
            if (i+1 >= argc) {
                fprintf(stderr, "-o requires an argument!\n");
                exit(EXIT_FAILURE);
            }
            if (sscanf(argv[++i], "%hu", &ssl_port) != 1) {
                fprintf(stderr, "Invalid HTTPS port!\n");
                goto help;
            }
            ssl_port = htons(ssl_port);
        }
        else {
            fprintf(stderr, "Warning! Unknown option `%s'!\n", argv[i]);
        }
    }

    if (ssl && (ssl_cert == NULL || ssl_priv_key == NULL)) {
        fprintf(stderr, "SSL requires both a certificate and a private key!\n");
        goto help;
    }

    if (port == ssl_port) {
        fprintf(stderr, "HTTP port is the same as HTTPS, cannot continue!\n");
        exit(EXIT_FAILURE);
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

    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)); // skips the TIME_WAIT state
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &true, sizeof(int)); // allows to have multiple servers handling multiple domains on the same port

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
    if(ssl) {
        socket_fd_ssl = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd_ssl < 0) {
            perror("Failed to create TCP socket!(SSL) ");
            exit(EXIT_FAILURE);
        }

        setsockopt(socket_fd_ssl, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int));
        setsockopt(socket_fd_ssl, SOL_SOCKET, SO_REUSEPORT, &true, sizeof(int));

        addr_ssl = (struct sockaddr_in){
            .sin_addr = ip,
            .sin_port = ssl_port,
            .sin_family = AF_INET,
            .sin_zero = {0}
        };

        if (bind(socket_fd_ssl, (struct sockaddr *) &addr_ssl, sizeof(struct sockaddr_in)) < 0) {
            perror("Failed to bind to IP/port!(SSL) ");
            exit(EXIT_FAILURE);
        }
    
    }
    unsigned int addr_size = sizeof(struct sockaddr_in);

    int conn_fd = -1;
    
    assert(listen(socket_fd, MAX_CLIENTS) != -1);
    if (ssl) assert(listen(socket_fd_ssl, MAX_CLIENTS) != -1);

    fprintf(stderr, "Running server on %s:%hu\n", ip_str, htons(port));
    if (ssl)
        fprintf(stderr, "Running server over TLS on %s:%hu\n", ip_str, htons(ssl_port));

    time_t conn_time = 0;

    char time_char[256] = {0};


    fd_set set;

    FD_ZERO(&set);
    FD_SET(socket_fd, &set);
    if (ssl) FD_SET(socket_fd_ssl, &set);

    errno = 0;

    char connect_is_ssl = 0;

    while (select(ssl?MAX(socket_fd, socket_fd_ssl)+1:socket_fd+1, &set, NULL, NULL, NULL) != -1 || errno == EINTR) {
        if (errno == EINTR) {  // select throws EINTR on SIGCHLD from server thread
            errno = 0;
            FD_SET(socket_fd, &set);
            if (ssl) FD_SET(socket_fd_ssl, &set);
            continue;
        }

        if (ssl && FD_ISSET(socket_fd_ssl, &set)) {
            FD_SET(socket_fd, &set);
            connect_is_ssl = 1;
            conn_fd = accept(socket_fd_ssl, (struct sockaddr *) &addr, &addr_size);
        } else {
            if (ssl) FD_SET(socket_fd_ssl, &set);
            connect_is_ssl = 0;
            conn_fd = accept(socket_fd, (struct sockaddr *) &addr, &addr_size);
        }

        if (child_count > MAX_CLIENTS) {
            fprintf(stderr, "WARNING: Maximum client count reached, refusing new connection...\n");
            shutdown(conn_fd, SHUT_RDWR);
            close(conn_fd);
            continue;
        }
        
        child_count ++;
        inet_ntop(addr.sin_family, &addr.sin_addr, ip_client, 16);
        time(&conn_time);
        strncpy(time_char, ctime(&conn_time), MIN(256, strlen(ctime(&conn_time))-1));
        fprintf(stderr, "[%s] Recieved connection from %s:%d\n", time_char, ip_client, htons(addr.sin_port));

        switch (fork()) {
            case 0: // child
                if (!connect_is_ssl) server(conn_fd);
                else ssl_wrapper(conn_fd);
                exit(EXIT_SUCCESS);
                break;
            default:
                close(conn_fd);
                break;
        }
    } 

    perror("Server stopped: ");
    return errno;
}