#ifndef HKDF_H
#define HKDF_H
#include "hmac.h"
#include <stddef.h>

struct prk { // free prk after use
    unsigned char * prk;
    size_t prk_len; //hash_len
};

__attribute__((warn_unused_result)) struct prk hkdf_extract(enum hmac_supported_hashes hash_type, const unsigned char * salt, size_t salt_len, const unsigned char * initial_keying_material, size_t ikm_len); // returns pseudorandom key, length determined by hash_type
__attribute__((warn_unused_result)) unsigned char * hkdf_expand(enum hmac_supported_hashes hash_type, struct prk prk, const unsigned char * info, size_t info_len, size_t output_key_len);
void hkdf_free(struct prk prk);
#endif