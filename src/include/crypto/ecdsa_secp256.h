#ifndef ECDSA_SECP256_H
#define ECDSA_SECP256_H

#include "secp256.h"
#include "hmac.h"
#define ECDSA_SECP256_SIG_SIZE SECP256_PRIVKEY_SIZE

struct ECDSA_signature {
    unsigned char * r, * s;
};

struct ECDSA_signature ecdsa_sign_secp256r1(
        enum hmac_supported_hashes hash_type, 
        const unsigned char * data, size_t data_len, 
        unsigned char * nonce, size_t nonce_len, 
        struct secp_key private_key);

#endif