#ifndef TLS_WRAPPER_H
#define TLS_WRAPPER_H
// public facing tls wrapper headers

char ssl_wrapper(int socket_fd, void (*wrapped_func)(int socket_fd));

#endif