#include "../crypto/include/ecdsa_secp256.h"
#include "../crypto/include/hmac.h"

#include "include/tls_crypto.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "include/memstructs.h"

// randomly generated privkey and public key using openssl
// priv d3523ec4d766b06f0f83c86844aeb7f7eb896364da6e8e7d3312c43d462433e2
// pub 04475bb2c0e67b1cbb713f97e720208935dd7927da9b9a4e554f84a4a1da3dbc5fdd2133f4376be27f3edde8397a446524d2a78681a4de9032addc48e6d7cc65d4
static unsigned char privkey[] = "\xd3\x52\x3e\xc4\xd7\x66\xb0\x6f\x0f\x83\xc8\x68\x44\xae\xb7\xf7\xeb\x89\x63\x64\xda\x6e\x8e\x7d\x33\x12\xc4\x3d\x46\x24\x33\xe2";
static unsigned char pubkey[] = "\x04\x47\x5b\xb2\xc0\xe6\x7b\x1c\xbb\x71\x3f\x97\xe7\x20\x20\x89\x35\xdd\x79\x27\xda\x9b\x9a\x4e\x55\x4f\x84\xa4\xa1\xda\x3d\xbc\x5f\xdd\x21\x33\xf4\x37\x6b\xe2\x7f\x3e\xdd\xe8\x39\x7a\x44\x65\x24\xd2\xa7\x86\x81\xa4\xde\x90\x32\xad\xdc\x48\xe6\xd7\xcc\x65\xd4";

int main() {
    struct secp_key temp_sig_key = {
        .private_key = privkey
    };
    printf("Testing ASN.1 wrapped SHA384 ECDSA sign using secp256r1 on text \"ecdsa sign test\"\nASN.1: ");
    Vector asn1_sign = asn1_wrap_secp256r1_sign(HMAC_SHA2_384, (unsigned char *)"ecdsa sign test", 15, temp_sig_key);
    assert(asn1_sign.data);

    for (size_t i = 0; i < asn1_sign.len; i++) {
        printf("%02hhx", ((unsigned char*)asn1_sign.data)[i]);
    }
    printf("\n");
}