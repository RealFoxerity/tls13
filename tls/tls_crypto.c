#include "include/tls_crypto.h"
#include "../crypto/include/aes.h"
#include "../crypto/include/hmac.h"
#include "include/tls_internal.h"
#include "include/memstructs.h"
#include "../crypto/include/secp256.h"
#include "../crypto/include/sha2.h"
#include "../crypto/include/hkdf.h"
#include "include/hkdf_tls.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

// TODO: if/when implementing PSK change first HKDF-extract to not use an empty block for IKM for PSK
// https://www.rfc-editor.org/rfc/rfc8446#section-7.1
void generate_server_secrets(struct tls_context * tls_context) { // has to be a different function since it requires the transcript hash to be up-to-date
    unsigned char * null_block = NULL;
    unsigned char * null_hash = NULL;
    unsigned char * transcript_hash  = NULL;

    size_t hash_len;
    enum hmac_supported_hashes hash_type;

    switch (tls_context->chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            fprintf(stderr, "Generating keys for AES-128-GCM-SHA256\n");
            hash_len = SHA256_HASH_BYTES;
            hash_type = HMAC_SHA2_256;
            null_hash = malloc(SHA256_HASH_BYTES);
            assert(null_hash);
            sha256_sum(null_hash, NULL, 0);

            transcript_hash = malloc(SHA256_HASH_BYTES);
            assert(transcript_hash);
            sha256_finalize(&tls_context->transcript_hash_ctx, transcript_hash);
            break;
        case TLS_AES_256_GCM_SHA384:
            fprintf(stderr, "Generating keys for AES-256-GCM-SHA384\n");
            hash_len = SHA384_HASH_BYTES;
            hash_type = HMAC_SHA2_384;
            null_hash = malloc(SHA384_HASH_BYTES);
            assert(null_hash);
            sha384_sum(null_hash, NULL, 0);

            transcript_hash = malloc(SHA384_HASH_BYTES);
            assert(transcript_hash);
            sha384_finalize(&tls_context->transcript_hash_ctx, transcript_hash);
            break;
        default:
            fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            exit(-AD_HANDSHAKE_FAILURE);
    }
    fprintf(stderr, "Transcript hash: ");
    for (int i = 0; i < hash_len; i++) {
        fprintf(stderr, "%02hhx ", transcript_hash[i]);
    }

    null_block = calloc(hash_len, 1);
    assert(null_block);

    tls_context->early_secret = hkdf_extract(hash_type, NULL, 0, null_block, hash_len);
    assert(tls_context->early_secret.prk);

    // for PSK also
    // derive binder key
    // derive client early traffic secret
    // derive early exporter master secret

    unsigned char * hs_ikm = hkdf_expand_label(hash_type, tls_context->early_secret, (unsigned char *)"derived", 7, null_hash, hash_len, hash_len);
    assert(hs_ikm);

    tls_context->handshake_secret = hkdf_extract(hash_type, hs_ikm, hash_len, tls_context->master_key.data, tls_context->master_key.len);
    assert(tls_context->handshake_secret.prk);

    tls_context->client_hs_traffic_secret.data = hkdf_expand_label(hash_type, tls_context->handshake_secret, (unsigned char *)"c hs traffic", 12, transcript_hash, hash_len, hash_len);    
    assert(tls_context->client_hs_traffic_secret.data);
    tls_context->client_hs_traffic_secret.len = hash_len;

    tls_context->server_hs_traffic_secret.data = hkdf_expand_label(hash_type, tls_context->handshake_secret, (unsigned char *)"s hs traffic", 12, transcript_hash, hash_len, hash_len);    
    assert(tls_context->server_hs_traffic_secret.data);
    tls_context->server_hs_traffic_secret.len = hash_len;

    unsigned char * ms_ikm = hkdf_expand_label(hash_type, tls_context->handshake_secret, (unsigned char *)"derived", 7, null_hash, hash_len, hash_len);
    assert(ms_ikm);

    tls_context->master_secret = hkdf_extract(hash_type, ms_ikm, hash_len, null_block, hash_len);
    assert(tls_context->master_secret.prk);
    // for PSK
    // derive exporter master key
    // for 0-rtt
    // derive resumption master key

    fprintf(stderr, "\nGenerated server secrets:\n");
    fprintf(stderr, "Early secret: ");
    for (int i = 0; i < tls_context->early_secret.prk_len; i++) {
        fprintf(stderr, "%02hhx ", tls_context->early_secret.prk[i]);
    }
    fprintf(stderr, "\nDerived secret: ");
    for (int i = 0; i < hash_len; i++) {
        fprintf(stderr, "%02hhx ", hs_ikm[i]);
    }
    fprintf(stderr, "\nHandshake secret: ");
    for (int i = 0; i < tls_context->handshake_secret.prk_len; i++) {
        fprintf(stderr, "%02hhx ", tls_context->handshake_secret.prk[i]);
    }
    fprintf(stderr, "\nMaster secret: ");
    for (int i = 0; i < tls_context->master_secret.prk_len; i++) {
        fprintf(stderr, "%02hhx ", tls_context->master_secret.prk[i]);
    }
    fprintf(stderr, "\n\nClient handshake traffic secret: ");
    for (int i = 0; i < tls_context->client_hs_traffic_secret.len; i++) {
        fprintf(stderr, "%02hhx ", ((unsigned char *)tls_context->client_hs_traffic_secret.data)[i]);
    }
    fprintf(stderr, "\nServer handshake traffic secret: ");
    for (int i = 0; i < tls_context->server_hs_traffic_secret.len; i++) {
        fprintf(stderr, "%02hhx ", ((unsigned char *)tls_context->server_hs_traffic_secret.data)[i]);
    }
    fprintf(stderr, "\n\n");
    free(hs_ikm);
    free(ms_ikm);
    free(null_block);
    free(null_hash);
    free(transcript_hash);
}

void generate_server_app_secrets(struct tls_context * tls_context) { // has to be done after Finalize message
    assert(tls_context->master_secret.prk);

    Vector transcript_hash = get_transcript_hash();
    assert(transcript_hash.data);
    enum hmac_supported_hashes hash_type = get_transcript_hash_type();
    assert(hash_type);

    tls_context->client_application_secret_0.data = hkdf_expand_label(hash_type, tls_context->master_secret, (unsigned char *)"c ap traffic", 12,
        transcript_hash.data, transcript_hash.len, transcript_hash.len);

    tls_context->client_application_secret_0.len = transcript_hash.len;

    tls_context->server_application_secret_0.data = hkdf_expand_label(hash_type, tls_context->master_secret, (unsigned char *)"s ap traffic", 12,
        transcript_hash.data, transcript_hash.len, transcript_hash.len);

    tls_context->server_application_secret_0.len = transcript_hash.len;
    free(transcript_hash.data);
}

int generate_server_keys(struct tls_context * tls_context) {
    if (tls_context->client_key_share.group != NG_SECP256R1) {
        fprintf(stderr, "Unsupported key share group!\n");
        return -AD_HANDSHAKE_FAILURE;
    }

    fprintf(stderr, "Generating secp256r1 keys\n");

    struct secp_key keys = secp256_gen_public_key();
    assert(keys.public_key);
    assert(keys.private_key);

    tls_context->server_ecdhe_keys.private_key.len = SECP256_PRIVKEY_SIZE;
    tls_context->server_ecdhe_keys.private_key.data = keys.private_key;

    tls_context->server_ecdhe_keys.public_key.len = SECP256_PUBKEY_SIZE;
    tls_context->server_ecdhe_keys.public_key.data = keys.public_key;

    tls_context->server_key_share.group = NG_SECP256R1;
    tls_context->server_key_share.key_exchange.len = SECP256_PUBKEY_SIZE;
    tls_context->server_key_share.key_exchange.data = keys.public_key;

    tls_context->master_key.len = SECP256_PRIVKEY_SIZE;
    tls_context->master_key.data = secp256_get_shared_key(tls_context->server_ecdhe_keys.private_key.data, tls_context->client_key_share.key_exchange.data);
    assert(tls_context->master_key.data);

    fprintf(stderr, "Generated ECDSA keys:\n\tserver private: ");
    for (int i = 0; i < tls_context->server_ecdhe_keys.private_key.len; i++) {
        fprintf(stderr, "%02hhx", ((unsigned char*)tls_context->server_ecdhe_keys.private_key.data)[i]);
    }
    fprintf(stderr, "\n\tserver public: ");
    for (int i = 0; i < tls_context->server_ecdhe_keys.public_key.len; i++) {
        fprintf(stderr, "%02hhx", ((unsigned char*)tls_context->server_ecdhe_keys.public_key.data)[i]);
    }
    
    fprintf(stderr, "\n\tclient public: ");
    for (int i = 0; i < tls_context->client_key_share.key_exchange.len; i++) {
        fprintf(stderr, "%02hhx", ((unsigned char*)tls_context->client_key_share.key_exchange.data)[i]);
    }
    fprintf(stderr, "\n\tshared key: ");
    for (int i = 0; i < tls_context->master_key.len; i++) {
        fprintf(stderr, "%02hhx", ((unsigned char*)tls_context->master_key.data)[i]);
    }
    fprintf(stderr, "\n");
    return 0;
}

void generate_traffic_keys(struct tls_context * tls_context, Vector client_secret, Vector server_secret) {
    // https://www.rfc-editor.org/rfc/rfc8446#section-7.3
    enum hmac_supported_hashes hash_type = get_transcript_hash_type();
    if (hash_type < 0) abort();
    
    int iv_len = get_cipher_iv_len();
    if (iv_len < 0) abort();

    int key_len = get_cipher_key_len();
    if (hash_type < 0) abort();
    
    struct prk cs = (struct prk) {
        .prk = client_secret.data,
        .prk_len = client_secret.len
    };

    struct prk ss = (struct prk) {
        .prk = server_secret.data,
        .prk_len = server_secret.len
    };

    free(tls_context->client_write_iv.data);
    free(tls_context->client_write_key.data);

    free(tls_context->server_write_iv.data);
    free(tls_context->server_write_key.data);

    tls_context->client_write_key.data = hkdf_expand_label(hash_type, cs, (unsigned char *)"key", 3, NULL, 0, key_len);
    tls_context->client_write_key.len = key_len;
    
    tls_context->client_write_iv.data = hkdf_expand_label(hash_type, cs, (unsigned char *)"iv", 2, NULL, 0, iv_len);
    tls_context->client_write_iv.len = iv_len;


    tls_context->server_write_key.data = hkdf_expand_label(hash_type, ss, (unsigned char *)"key", 3, NULL, 0, key_len);
    tls_context->server_write_key.len = key_len;
    
    tls_context->server_write_iv.data = hkdf_expand_label(hash_type, ss, (unsigned char *)"iv", 2, NULL, 0, iv_len);
    tls_context->server_write_iv.len = iv_len;

    tls_context->recv_message_counter = tls_context->txd_message_counter = 0;

    fprintf(stderr, "New traffic keys:\ntls_context->server_write_key: ");
    for (int i = 0; i < tls_context->server_write_key.len; i++) {
        fprintf(stderr, "%02hhx ", ((unsigned char *)tls_context->server_write_key.data)[i]);
    }
    fprintf(stderr, "\ntls_context->server_write_iv: ");
    for (int i = 0; i < tls_context->server_write_iv.len; i++) {
        fprintf(stderr, "%02hhx ", ((unsigned char *)tls_context->server_write_iv.data)[i]);
    }

    fprintf(stderr, "\ntls_context->client_write_key: ");
    for (int i = 0; i < tls_context->client_write_key.len; i++) {
        fprintf(stderr, "%02hhx ", ((unsigned char *)tls_context->client_write_key.data)[i]);
    }
    fprintf(stderr, "\ntls_context->client_write_iv: ");
    for (int i = 0; i < tls_context->client_write_iv.len; i++) {
        fprintf(stderr, "%02hhx ", ((unsigned char *)tls_context->client_write_iv.data)[i]);
    }
    fprintf(stderr, "\n");
}

int get_cipher_iv_len() {
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
        case TLS_AES_256_GCM_SHA384:
            return AES_GCM_DEFAULT_IV_LEN;
        default:
           fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            return -AD_HANDSHAKE_FAILURE;
    }
}

int get_cipher_key_len() {
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            return AES_128_KEY_LEN;
        case TLS_AES_256_GCM_SHA384:
            return AES_256_KEY_LEN;
        default:
            fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            return -AD_HANDSHAKE_FAILURE;
    }
}

int get_transcript_hash_len() {
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            return SHA256_HASH_BYTES;
        case TLS_AES_256_GCM_SHA384:
            return SHA384_HASH_BYTES;
        default:
            fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            return -AD_HANDSHAKE_FAILURE;
    }
}

enum hmac_supported_hashes get_transcript_hash_type() {
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            return HMAC_SHA2_256;
        case TLS_AES_256_GCM_SHA384:
            return HMAC_SHA2_384;
        default:
            fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            return -AD_HANDSHAKE_FAILURE;
    }
}

size_t print_hex_buf(const unsigned char * buf, size_t len);

int init_transcript_hash() {
    fprintf(stderr, "Init transcript hash\n");
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            sha256_init(&tls_context.transcript_hash_ctx);
            break;
        case TLS_AES_256_GCM_SHA384:
            sha384_init(&tls_context.transcript_hash_ctx);
            break;
        default:
            fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            return -AD_HANDSHAKE_FAILURE;
    }

    return 0;
}
int update_transcript_hash(const unsigned char * buffer, size_t n) {
    fprintf(stderr, "Updating transcript hash with:\n");
    print_hex_buf(buffer, n);
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            sha256_update(&tls_context.transcript_hash_ctx, buffer, n);
            break;
        case TLS_AES_256_GCM_SHA384:
            sha384_update(&tls_context.transcript_hash_ctx, buffer, n);
            break;
        default:
            fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            return -AD_HANDSHAKE_FAILURE;
    }
    return 0;
}

Vector get_transcript_hash() {
    Vector out;
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            out.len = SHA256_HASH_BYTES;
            out.data = malloc(SHA256_HASH_BYTES);
            assert(out.data);
            sha256_finalize(&tls_context.transcript_hash_ctx, out.data);
            break;
        case TLS_AES_256_GCM_SHA384:
            out.len = SHA384_HASH_BYTES;
            out.data = malloc(SHA384_HASH_BYTES);
            assert(out.data);
            sha384_finalize(&tls_context.transcript_hash_ctx, out.data);
            break;
        default:
            fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            return (Vector) {
                .data = NULL,
                .len = -AD_HANDSHAKE_FAILURE
            };
    }
    return out;
}