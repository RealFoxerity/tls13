#ifndef HMAC_H
#define HMAC_H
#include <stddef.h>

enum hmac_supported_hashes { // TODO: add more for completion, shouldn't be needed for TLS though
    HMAC_SHA1,
    HMAC_SHA2_224,
    HMAC_SHA2_256,
    HMAC_SHA2_384,
    HMAC_SHA2_512,
};

unsigned char * hmac(enum hmac_supported_hashes hash_type, const unsigned char * key, size_t key_len, const unsigned char * in, size_t in_len);

#endif