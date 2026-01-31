//https://www.rfc-editor.org/rfc/rfc5869
#include "include/hkdf.h"
#include "include/hmac.h"
#include "include/sha2.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

__attribute__((warn_unused_result)) struct prk hkdf_extract(enum hmac_supported_hashes hash_type, const unsigned char * salt, size_t salt_len, const unsigned char * initial_keying_material, size_t ikm_len) {
    struct prk out = {0};
        switch (hash_type) {
        case HMAC_SHA1:
            out.prk_len = SHA1_HASH_BYTES;
            break;
        case HMAC_SHA2_224:
            out.prk_len = SHA224_HASH_BYTES;
            break;
        case HMAC_SHA2_256:
            out.prk_len = SHA256_HASH_BYTES;
            break;
        case HMAC_SHA2_384:
            out.prk_len = SHA384_HASH_BYTES;
            break;
        case HMAC_SHA2_512:
            out.prk_len = SHA512_HASH_BYTES;
            break;
        default:
            fprintf(stderr, "Hash type %d not allowable for HKDF\n", hash_type);
            return out;
    }
    out.prk = hmac(hash_type, salt, salt_len, initial_keying_material, ikm_len); // ordering is correct, even though it doesn't make sense, check rfc 5869 start of 2.1.
    return out;
}

__attribute__((warn_unused_result)) unsigned char * hkdf_expand(enum hmac_supported_hashes hash_type, struct prk prk, const unsigned char * info, size_t info_len, size_t output_key_len) {
    assert(output_key_len > 0 && output_key_len <= 255*prk.prk_len);
    // TODO: check whether prk.prk_len is the same as hash_type hash len !!!!

    if (output_key_len%prk.prk_len != 0) output_key_len += prk.prk_len - output_key_len%prk.prk_len; // dirty trick to simplify logic, doesn't matter anyway but results in up to 31 bytes wasted
    unsigned char * temp_block = calloc(prk.prk_len + info_len + 1, 1);
    unsigned char * temp_hmac = NULL;
    assert(temp_block);
    memcpy(temp_block + prk.prk_len, info, info_len);

    unsigned char * okm = calloc(output_key_len, 1);
    assert(okm);

    temp_block[prk.prk_len + info_len] = 0x01;

    temp_hmac = hmac(hash_type, prk.prk, prk.prk_len, temp_block + prk.prk_len, info_len + 1); // block 1 uses an empty T as the first element
    memcpy(okm, temp_hmac, prk.prk_len);
    free(temp_hmac);

    for (size_t i = 1; i < output_key_len/prk.prk_len; i++) {
        memcpy(temp_block, okm + (i-1)*prk.prk_len, prk.prk_len);
        temp_block[prk.prk_len + info_len] = i+1;
        temp_hmac = hmac(hash_type, prk.prk, prk.prk_len, temp_block, prk.prk_len + info_len + 1);
        memcpy(okm + i*prk.prk_len, temp_hmac, prk.prk_len);
        free(temp_hmac);
    }

    free(temp_block);

    return okm;
}

void hkdf_free(struct prk prk) {free(prk.prk);}