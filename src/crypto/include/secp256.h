#ifndef SECP256_H
#define SECP256_H

#define SECP256_PRIVKEY_SIZE 32 // bytes, also the maximum size of a single point
#define SECP256_PUBKEY_SIZE 65 // structure: 04:<key X>:<key Y>
#include "../../include/tls_internal.h" // for ESDSA_UNCOMPRESSED_POINT_FORMAT 
struct secp_key { // use free to deallocate
    unsigned char * private_key;
    unsigned char * public_key;
};

struct secp_key secp256_gen_public_key();
unsigned char * secp256_get_shared_key(const unsigned char * private_key, const unsigned char * bob_public_key);

#endif