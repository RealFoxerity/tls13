#ifndef SECP256_H
#define SECP256_H

#define SECP256_PRIVKEY_SIZE 32 // bytes, also the maximum size of a single point
#define SECP256_PUBKEY_SIZE 65 // structure: 04:<key X>:<key Y>
#include "../tls.h" // for ESDSA_UNCOMPRESSED_POINT_FORMAT 
struct secp_key { // use free to deallocate
    unsigned char * private_key;
    unsigned char * public_key;
};

#endif