#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "../crypto/include/hmac.h"
#include "../crypto/include/secp256.h"
#include "include/asn.1.h"
#include "include/memstructs.h"
#include "include/tls.h"
#include "include/tls_internal.h"
#include "include/x.509.h"
#include "include/x9.62.h"

char ssl_load_cert(const char * cert_path, const char * privkey_path) {
    FILE * cert_file = fopen(cert_path, "r");
    if (!cert_file) {
        perror("Failed to open SSL certificate: ");
        return errno;
    }
    FILE * privkey_file = fopen(privkey_path, "r");
    if (!privkey_file) {
        perror("Failed to open SSL private key: ");
        return errno;
    }
    fseek(cert_file, 0, SEEK_END);
    fseek(privkey_file, 0, SEEK_END);
    size_t cert_len = ftell(cert_file);
    size_t privkey_len = ftell(privkey_file);
    if (cert_len == 0 || privkey_len == 0) {
        fprintf(stderr, "0 length SSL certificate!\n");
        fclose(cert_file);
        fclose(privkey_file);
        return EXIT_FAILURE;
    }
    rewind(cert_file);
    rewind(privkey_file);

    tls_context.cert = malloc(cert_len);
    assert(tls_context.cert);
    fread(tls_context.cert, 1, cert_len, cert_file);
    fclose(cert_file);
    tls_context.cert_len = cert_len;

    unsigned char * privkey = malloc(privkey_len);
    assert(privkey);
    fread(privkey, 1, privkey_len, privkey_file);
    fclose(privkey_file);

    asn1_print_structure(tls_context.cert, tls_context.cert_len);
    asn1_print_structure(privkey, privkey_len);
    enum x962_prime_curve_names curve;
    
    if (x509_load_cert(tls_context.cert, tls_context.cert_len, privkey, privkey_len, &tls_context.cert_keys, &curve) != X509_LOADED) return EXIT_FAILURE;

    switch (curve) {
        case X962_PRIME_CURVE_NAME_PRIME256V1:
            assert(tls_context.cert_keys.private_key.len == SECP256_PRIVKEY_SIZE);
            assert(tls_context.cert_keys.public_key.len == SECP256_PUBKEY_SIZE);
            tls_context.cert_key_type = NG_SECP256R1;
            break;
        default:
            fprintf(stderr, "Error: certificate uses currently unsupported key type, only prime256v1/secp256r1 is currently implemented\n");
            return EXIT_FAILURE;
    }
    fprintf(stderr, "Using certificate private key:\n");
    for (int i = 0; i < tls_context.cert_keys.private_key.len; i++) {
        fprintf(stderr, "%02hhx", ((unsigned char*)tls_context.cert_keys.private_key.data)[i]);
    }
    fprintf(stderr, "\nUsing certificate public key:\n");
    for (int i = 0; i < tls_context.cert_keys.public_key.len; i++) {
        fprintf(stderr, "%02hhx", ((unsigned char*)tls_context.cert_keys.public_key.data)[i]);
    }
    printf("\n");

    free(privkey);
    return 0;
}