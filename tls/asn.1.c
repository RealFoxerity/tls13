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
    [ASN1_BIT_STRING] = ASN1_PRIMITVE, // DER enforces primitive form, BER supports both
    [ASN1_OCTET_STRING] = ASN1_PRIMITVE, // same
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
        
        for (int i = added_len_bytes - 2; i >= 0; i--) {
           out[2 + i] = (n >> (i*8)) & 0xFF;
        }
    }

    Vector rec = {
        .data = out,
        .len = 1 + added_len_bytes + n
    };
    return rec;
}

struct asn1_node asn1_get_next(const unsigned char * object_start, size_t maxlen) {
    if (maxlen < 3) return (struct asn1_node) {0};

    size_t offset = 0;

    struct asn1_node out = {0};
    out.tag_class = object_start[0] >> 6;
    if (object_start[0] & 0x20) out.constructed = 1;
    if ((object_start[0] & 0x1F) == 0x1F) { // long mode tag id
        do {
            if (++offset >= maxlen) return (struct asn1_node) {0};
            out.tag <<= 7;
            out.tag |= object_start[offset] & 0x7F;
        } while(object_start[offset] & 0x80);
    } else out.tag = object_start[0] & 0x1F;

    if (++offset >= maxlen) return (struct asn1_node) {0};
    if (object_start[offset] == 0x80 || object_start[offset] == 0xFF) return (struct asn1_node) {0}; // we don't support indefinite, 0xFF is reserved

    if (object_start[offset] & 0x80) {
        int length_bytes = object_start[offset] & 0x7F;

        if (length_bytes > 9) return (struct asn1_node) {0}; // resulting length would be larger than 64 bit int, probably not correct :P

        for (int i = 0; i < length_bytes; i++) {
            if (++offset >= maxlen) return (struct asn1_node) {0};
            out.len <<= 8;
            out.len |= object_start[offset];
        }
    } else {
        out.len = object_start[offset] & 0x7F;
    }

    if (++offset >= maxlen) return (struct asn1_node) {0};
        
    out.header_len = offset;
    if (out.len + out.header_len > maxlen) return (struct asn1_node) {0};


    out.data = object_start + offset;
    return out;
}

#include <stdio.h>


static char asn1_print_node(const unsigned char * data, size_t *offset, size_t n) {
    static int tab_depth = 0;
    assert(data);
    assert(offset);

    if (*offset >= n) return 0;

    struct asn1_node node = asn1_get_next(data + *offset, n-*offset);
    if (node.data == NULL || node.len == 0) return 0;

    *offset = node.data - data;

    for (int i = 0; i < tab_depth; i++) fprintf(stderr,"  ");

    fprintf(stderr, "t %04x:%s, l %lu%s", node.tag, 
            node.tag_class == ASN1_TAG_UNIVERSAL ? "UNIV":
            node.tag_class == ASN1_TAG_APPLICATION ? "APP":
            node.tag_class == ASN1_TAG_CONTEXT_SPECIFIC ? "CTX": 
            "priv",
        node.len, 
            node.constructed ? ":\n":
            ", data: "
    );

    if (!node.constructed) {
        for (size_t i = 0; i < node.len; i++) {
            fprintf(stderr, "%02hhx:", node.data[i]);
        }
        putc('\n', stderr);
        *offset += node.len;
    } else {
        tab_depth ++;
        size_t old_off = *offset;
        while (*offset - old_off < node.len) {
            if (!asn1_print_node(data, offset, n)) return 0;
        }
        tab_depth --;
    }
    return 1;
}

void asn1_print_structure(const unsigned char * data, size_t n) {
    fprintf(stderr, "\n\n----- ASN.1 STRUCTURE -----\n");
    size_t off = 0;
    while (off < n) if (asn1_print_node(data, &off, n) == 0) {fprintf(stderr, "##### INVALID/BROKEN/UNSUPPORTED CERTIFICATE #####"); return;};
}