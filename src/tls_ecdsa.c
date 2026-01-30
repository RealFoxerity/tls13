#include "crypto/include/ecdsa_secp256.h"
#include "crypto/include/hmac.h"
#include "crypto/include/secp256.h"
#include "include/asn.1.h"

#include "include/tls_crypto.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
according to https://www.rfc-editor.org/rfc/rfc8446 4.2.3, ECDSA signatures are to be encoded using ASN.1 der encoded ECDSA-Sig-Value
ECDSA-Sig-Value is referenced in https://www.rfc-editor.org/rfc/rfc3278 in other syntax 8.2, but primarily is defined in ANSI X9.62-1998
according to X9.62 the structure is as follows:

ECDSA-Sig-Value ::= SEQUENCE {
    r INTEGER,
    s INTEGER
}

where r and s are the 2 return values from ecdsa sign as defined in FIPS 186-5
*/
Vector asn1_wrap_secp256r1_sign(enum hmac_supported_hashes hash_type, const unsigned char * data, size_t n, struct secp_key private_key) {
    assert(data);
    assert(private_key.private_key);
    
    struct ECDSA_signature signature = ecdsa_sign_secp256r1(hash_type, data, n, private_key);
    assert(signature.r);
    assert(signature.s);

    Vector wrapped_r = asn1_der_wrap_element(signature.r, ECDSA_SECP256_SIG_SIZE, ASN1_INTEGER);
    Vector wrapped_s = asn1_der_wrap_element(signature.s, ECDSA_SECP256_SIG_SIZE, ASN1_INTEGER);
    assert(wrapped_r.data);
    assert(wrapped_s.data);

    free(signature.r);
    free(signature.s);

    unsigned char * inner_data = malloc(wrapped_r.len + wrapped_s.len);
    assert(inner_data);
    memcpy(inner_data, wrapped_r.data, wrapped_r.len);
    memcpy(inner_data + wrapped_r.len, wrapped_s.data, wrapped_s.len);

    free(wrapped_r.data);
    free(wrapped_s.data);

    Vector out = asn1_der_wrap_element(inner_data, wrapped_r.len + wrapped_s.len, ASN1_SEQUENCE);
    assert(out.data);
    free(inner_data);
    return out;
}