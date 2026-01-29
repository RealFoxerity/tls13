#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "include/asn.1.h"
#include "include/memstructs.h"
/*
ASN.1 is described in multiple standards
X.680 - Basic Notation
X.681 - Information Object Specification
X.682 - Constraint Specification
X.683 - Parametrization of ASN.1 Specifications

the encoding we want (DER) is then specified in X.690
note: DER is a subset of BER, so implementing BER with constraints is enough
note2: we won't be implementing EVERYTHING because that's 1000+ pages of standards 

I'm gonna be honest
i just used wikipedia to do the implementation, i'm sorry
https://en.wikipedia.org/wiki/X.690
*/

#define ASN1_BOTH 2
#define ASN1_CONSTRUCTED 1
#define ASN1_PRIMITVE 0
static const char tags_constructed[] = {
    //[ASN1_END_OF_CONTENT] = ASN1_PRIMITVE,
    [ASN1_BOOLEAN] = ASN1_PRIMITVE,
    [ASN1_INTEGER] = ASN1_PRIMITVE,
    [ASN1_BITSTRING] = ASN1_PRIMITVE, // DER enforces primitive form, BER supports both
    [ASN1_OCTETSTRING] = ASN1_PRIMITVE, // same
    [ASN1_NULL] = ASN1_PRIMITVE,
    [ASN1_OBJECT_IDENTIFIER] = ASN1_PRIMITVE,
    [ASN1_OBJECT_DESCRIPTOR] = ASN1_BOTH,
    [ASN1_SEQUENCE] = ASN1_CONSTRUCTED,
};

Vector asn1_der_wrap_element(const unsigned char * data, size_t n, enum asn1_tags tag) {
    if (tag > ASN1_SEQUENCE) return (Vector) {0};
    assert(tags_constructed[tag] != ASN1_BOTH); // not yet supported
    
    // we support only the universal tags, so upper 2 bits will be always 0
    // we also support only < 16 tag id, so no second id octet required
    unsigned char ident_octet = tag;
    if (tags_constructed[tag]) ident_octet |= 0b00100000;

    char added_len_bytes = 0;
    for (int i = 0; i < sizeof(uint64_t); i++) {
        if (n >> (8*i)) added_len_bytes ++;
    }

    if (n >= 1<<7) added_len_bytes++; // everything else needs a header of sorts

    unsigned char * out = calloc(1 + added_len_bytes + n, 1);
    assert(out);
    memcpy(out + 1 + added_len_bytes, data, n);
    out[0] = ident_octet;

    if (added_len_bytes == 1) { // don't need to add more len bytes
        out[1] = n;
    } else {
        out[1] = 0x80 | (added_len_bytes - 1);
        
        for (int i = added_len_bytes - 1; i >= 0; i--) {
           out[2 + i] = (n >> (i*8)) & 0xFF;
        }
    }

    Vector rec = {
        .data = out,
        .len = 1 + added_len_bytes + n
    };
    return rec;
}