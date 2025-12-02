//https://www.rfc-editor.org/rfc/rfc2104
#include "../include/crypto/hmac.h"
#include "../include/crypto/sha2.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#define IPAD_BYTE 0x36
#define OPAD_BYTE 0x5C

unsigned char * hmac(enum hmac_supported_hashes hash_type, const unsigned char * key, size_t key_len, const unsigned char * in, size_t in_len) {    
    void (*init)    (sha2_ctx_t * ctx);
    void (*update)  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len);
    void (*finalize)(sha2_ctx_t * ctx, unsigned char * hash_out);
    
    size_t hash_size = 0; // L
    size_t block_size = 0; // B

    switch (hash_type) {
        case HMAC_SHA1:
            fprintf(stderr, "HMAC using SHA-1 is not yet implemented\n");
            return NULL;

            /*
            hash_size = SHA1_HASH_BYTES;
            block_size = SHA256_MESSAGE_BLOCK/8;
            break;
            */
        case HMAC_SHA2_224:
            hash_size = SHA224_HASH_BYTES;
            init     = sha224_init;
            update   = sha224_update;
            finalize = sha224_finalize;
            block_size = SHA256_MESSAGE_BLOCK/8;
            break;
        case HMAC_SHA2_256:
            hash_size = SHA256_HASH_BYTES;
            init     = sha256_init;
            update   = sha256_update;
            finalize = sha256_finalize;
            block_size = SHA256_MESSAGE_BLOCK/8;
            break;
        case HMAC_SHA2_384:
            hash_size = SHA384_HASH_BYTES;
            init     = sha384_init;
            update   = sha384_update;
            finalize = sha384_finalize;
            block_size = SHA512_MESSAGE_BLOCK/8;
            break;
        case HMAC_SHA2_512:
            hash_size = SHA512_HASH_BYTES;
            init     = sha512_init;
            update   = sha512_update;
            finalize = sha512_finalize;
            block_size = SHA512_MESSAGE_BLOCK/8;
            break;
        default:
            fprintf(stderr, "Hash type %d not supported for HMAC\n", hash_type);
            return NULL;
    }

    assert(key_len <= block_size);

    unsigned char * padded_key = calloc(block_size, 1); // K
    assert(padded_key);

    unsigned char * hash = calloc(hash_size, 1);
    assert(hash);

    memcpy(padded_key, key, key_len);
    for (int i = 0; i < block_size; i++) {
        padded_key[i] ^= IPAD_BYTE;
    }

    sha2_ctx_t context_inner;
    init(&context_inner);

    update(&context_inner, padded_key, block_size);
    update(&context_inner, in, in_len);
    finalize(&context_inner, hash);

    for (int i = 0; i < block_size; i++) {
        padded_key[i] ^= IPAD_BYTE; // restore the previous key
        padded_key[i] ^= OPAD_BYTE;
    }
    init(&context_inner);
    update(&context_inner, padded_key, block_size);
    update(&context_inner, hash, hash_size);
    finalize(&context_inner, hash);

    free(padded_key);
    return hash;
}