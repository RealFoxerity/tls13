#ifndef ASN_1_H
#define ASN_1_H
#include "memstructs.h"
#include <stddef.h>

enum asn1_tags {
    //ASN1_END_OF_CONTENT, // not used in DER
    ASN1_BOOLEAN = 1,
    ASN1_INTEGER,
    ASN1_BIT_STRING,
    ASN1_OCTET_STRING,
    ASN1_NULL,
    ASN1_OBJECT_IDENTIFIER,
    ASN1_OBJECT_DESCRIPTOR,
    ASN1_SEQUENCE = 0x10
};

Vector asn1_der_wrap_element(const unsigned char * data, size_t n, enum asn1_tags tag);



enum asn1_tag_class {
    ASN1_TAG_UNIVERSAL,
    ASN1_TAG_APPLICATION,
    ASN1_TAG_CONTEXT_SPECIFIC,
    ASN1_TAG_PRIVATE,
};

struct asn1_node {
    enum asn1_tags tag;
    char constructed;
    enum asn1_tag_class tag_class;
    size_t len;
    size_t header_len;
    const unsigned char * data;
};

struct asn1_node asn1_get_next(const unsigned char * object_start, size_t maxlen);
void asn1_print_structure(const unsigned char * data, size_t n);
#endif