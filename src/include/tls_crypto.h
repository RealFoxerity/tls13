#ifndef TLS_CRYPTO_H
#define TLS_CRYPTO_H
#include "memstructs.h"
#include "tls_internal.h"

void generate_server_secrets(struct tls_context * tls_context);
void generate_server_app_secrets(struct tls_context * tls_context);
int generate_server_keys(struct tls_context * tls_context);
void generate_traffic_keys(struct tls_context * tls_context, Vector client_secret, Vector server_secret);

#endif