#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "include/tls.h"
#include "include/tls_internal.h"

char ssl_load_cert(const char * cert_path, const char * privkey_path) {
    FILE * cert_file = fopen(cert_path, "r");
    if (!cert_file) {
        perror("Failed to open SSL certificate: ");
        return errno;
    }
    fseek(cert_file, 0, SEEK_END);
    size_t cert_len = ftell(cert_file);
    if (cert_len == 0) {
        fprintf(stderr, "0 length SSL certificate!\n");
        fclose(cert_file);
        return EXIT_FAILURE;
    }
    rewind(cert_file);

    tls_context.cert = malloc(cert_len);
    assert(tls_context.cert);
    fread(tls_context.cert, 1, cert_len, cert_file);
    fclose(cert_file);
    tls_context.cert_len = cert_len;

    return 0;
}