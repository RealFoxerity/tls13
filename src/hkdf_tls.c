// https://www.rfc-editor.org/rfc/rfc8446#section-7.1
#include "include/crypto/hkdf.h"
#include "include/hkdf_tls.h"
#include <assert.h>
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// TODO: NOT YET TESTED, TEST

#define LABEL_START "tls13"
/*
struct {
    uint16 length = Length;
    opaque label<7..255> = "tls13 " + Label;
    opaque context<0..255> = Context;
} HkdfLabel;
 */
__attribute__((warn_unused_result)) unsigned char * hkdf_expand_label(enum hmac_supported_hashes hash_type, struct prk secret, const unsigned char * label, size_t label_len, const unsigned char * context, size_t context_len, uint16_t okm_len) {
    assert(label_len >= 2); // 7 minimum - 5 for tls13
    assert(label);
    assert(secret.prk);
    if (context_len != 0) assert(context);

    unsigned char * hkdf_label = malloc(sizeof(uint16_t) + label_len + 5 + context_len);
    assert(hkdf_label);

    *(uint16_t*)hkdf_label = htobe16(okm_len);
    memcpy(hkdf_label + sizeof(uint16_t), LABEL_START, sizeof(LABEL_START) - 1);
    memcpy(hkdf_label + sizeof(uint16_t) + sizeof(LABEL_START) - 1, label, label_len);
    if (context_len != 0) {
        memcpy(hkdf_label + sizeof(uint16_t) + sizeof(LABEL_START) - 1 + label_len, context, context_len);
    }

    unsigned char * okm = hkdf_expand(hash_type, secret, hkdf_label, sizeof(uint16_t) + sizeof(LABEL_START) - 1 + label_len + context_len, okm_len);

    free(hkdf_label);
    return okm;
} 
// unsigned char * hkdf_derive_secret(secret, label, messages); is the same as calling hkdf_expand_label(secret, label, running hash of messages, length of hash)