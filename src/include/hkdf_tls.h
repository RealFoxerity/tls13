#ifndef HKDF_TLS_H
#define HKDF_TLS_H
#include "../crypto/include/hkdf.h"
#include <stdint.h>

__attribute__((warn_unused_result)) unsigned char * hkdf_expand_label(enum hmac_supported_hashes hash_type, struct prk secret, const unsigned char * label, size_t label_len, const unsigned char * context, size_t context_len, uint16_t okm_len);

#endif