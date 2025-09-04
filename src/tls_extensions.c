#include "include/tls_extensions.h"
#include "include/tls.h"

#include <assert.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

char * parse_server_name_extension(unsigned char* buffer, unsigned short len) { // https://www.rfc-editor.org/rfc/rfc6066
    char * hostname = NULL;
    assert(len > 5);                                                // bare minimum, alert illegal_parameter
    unsigned short namelist_len = htons(*(short*)buffer);
    char nametype = buffer[2];                                      // always 0, no other values defined
    assert(nametype == 0);                                          // alert illegal_parameter
    unsigned short hostname_len = htons(*(short*)(buffer+3));
    assert(hostname_len<namelist_len);                              // alert decode_error
    assert(hostname_len<=len-5);                                    // alert decode_error
    hostname = malloc(hostname_len+1);
    memset(hostname, 0, hostname_len+1);
    assert(hostname!=NULL);                                         // alert illegal_parameter
    strncpy(hostname, (char*)(buffer+5), hostname_len);

    return hostname;
}

int parse_supported_versions_extension(unsigned char* buffer, unsigned short len) {
    unsigned short versions_len = buffer[0];
    assert(versions_len % 2 == 0 && versions_len >= 2); // alert illegal_parameter, decode_error
    assert(versions_len <= len-1); // alert decode_error

    for (int i = 1; i<len; i+=2) {
        if (htons(*(short*)&(buffer[i])) == 0x0304) return 0; // supports TLS 1.3
    }
    return 1;
}

Vector parse_extension_lenshort_mod2_generic(unsigned char * buffer, unsigned short len) {
    Vector out = {0};
    out.len = htons(*(unsigned short*)buffer);
    assert((out.len %2) == 0 && out.len <= len-2 && out.len >= 2); // alert illegal_parameter,, decode_error, decode_error
    out.data = malloc(out.len);
    assert(out.data != NULL); // alert illegal_parameter
    memcpy(out.data, buffer+2, out.len);
    return out;
}

Vector parse_extension_lenshort_generic(unsigned char * buffer, unsigned short len) {
    Vector out = {0};
    out.len = htons(*(unsigned short*)buffer);
    assert(out.len <= len-2); // alert decode_error
    out.data = malloc(out.len);
    assert(out.data != NULL); // alert illegal_parameter
    memcpy(out.data, buffer+2, out.len);
    return out;
}

Vector parse_supported_groups_extension(unsigned char *buffer, unsigned short len) {
    return parse_extension_lenshort_mod2_generic(buffer, len);
}
KeyShares parse_key_share_groups_extension(unsigned char *buffer, unsigned short len) { // kill me
    KeyShares out = {0};
    KeyShares * curr = &out;
    Vector base = {0};
    base = parse_extension_lenshort_generic(buffer, len);
    assert(base.data);

    for (int i = 0; i < base.len;) {
        assert(i+2 <= base.len);
        curr->node.group = htons(*(unsigned short*)(base.data+i));
        curr->node.key_exchange = parse_extension_lenshort_generic(base.data+i+2, base.len-i-2);
        assert(curr->node.key_exchange.len >=1);
        i+= 2+curr->node.key_exchange.len+2; 

        if (i < base.len-1) {
            curr->next = malloc(sizeof(struct KeyShareNode));
            assert(curr->next != NULL);
            memset(curr->next, 0, sizeof(struct KeyShareNode));
            curr = curr->next;
        } else {
            curr->next = NULL; // to be 100000% sure
        }
    }
    
    free(base.data);
    base.data = NULL;

    return out;
}

Vector parse_signature_algorithms_extension(unsigned char * buffer, unsigned short len) {
    return parse_extension_lenshort_mod2_generic(buffer, len);
}
Vector parse_psk_key_exchange_modes_extension(unsigned char * buffer, unsigned short len) {
    Vector out = {0};
    unsigned short pkem_len = buffer[0];
    assert(pkem_len >= 1); // alert decode_error
    assert(pkem_len <= len-1); // alert decode_error
    out.data = malloc(pkem_len);
    assert(out.data != NULL);

    memcpy(out.data, buffer + 1, pkem_len);
    return out;
}