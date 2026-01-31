#ifndef TLS_CRYPTO_H
#define TLS_CRYPTO_H
#include "memstructs.h"
#include "tls_internal.h"

void generate_server_secrets(struct tls_context * tls_context);
void generate_server_app_secrets(struct tls_context * tls_context);
int generate_server_keys(struct tls_context * tls_context);
void generate_traffic_keys(struct tls_context * tls_context, Vector client_secret, Vector server_secret);

#include "../../crypto/include/secp256.h"
Vector asn1_wrap_secp256r1_sign(enum hmac_supported_hashes hash_type, const unsigned char * data, size_t n, struct secp_key private_key);


int update_transcript_hash(const unsigned char * buffer, size_t n);
int init_transcript_hash();
Vector get_transcript_hash();
enum hmac_supported_hashes get_transcript_hash_type();
int get_transcript_hash_len();

int get_cipher_key_len();
int get_cipher_iv_len();
#endif