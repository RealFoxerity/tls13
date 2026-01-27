#ifndef TLS_H
#define TLS_H
// public facing tls wrapper headers

char ssl_wrapper(int socket_fd, void (*wrapped_func)(int socket_fd));
char ssl_load_cert(const char * cert_path, const char * privkey_path); // 0 = success
void ssl_cleanup();
#endif