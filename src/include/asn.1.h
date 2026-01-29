#ifndef ASN_1_H
#define ASN_1_H
#include "memstructs.h"
#include <stddef.h>

enum asn1_tags {
    //ASN1_END_OF_CONTENT, // not used in DER
    ASN1_BOOLEAN = 1,
    ASN1_INTEGER,
    ASN1_BITSTRING,
    ASN1_OCTETSTRING,
    ASN1_NULL,
    ASN1_OBJECT_IDENTIFIER,
    ASN1_OBJECT_DESCRIPTOR,
    ASN1_SEQUENCE = 0x10
};

Vector asn1_der_wrap_element(const unsigned char * data, size_t n, enum asn1_tags tag);

#endif