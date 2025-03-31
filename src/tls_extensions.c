#include "include/tls_extensions.h"
#include "include/tls.h"

#include <assert.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

const int supported_extensions_len = 3;
const unsigned short supported_extensions[] = {ET_SERVER_NAME, ET_HEARTBEAT, ET_SUPPORTED_VERSIONS, ET_PADDING};

char * parse_server_name_extension(unsigned char* buffer, unsigned short len) { // https://www.rfc-editor.org/rfc/rfc6066
    char * hostname = NULL;
    assert(len > 5); // bare minimum
    unsigned short namelist_len = htons(*(short*)buffer);
    char nametype = buffer[2]; // always 0, no other values defined
    assert(nametype == 0);
    unsigned short hostname_len = htons(*(short*)(buffer+3));
    assert(hostname_len<namelist_len);
    assert(hostname_len<=len-5);
    hostname = malloc(hostname_len+1);
    memset(hostname, 0, hostname_len+1);
    assert(hostname!=NULL);
    strncpy(hostname, (char*)(buffer+5), hostname_len);

    return hostname;
}

int parse_supported_versions_extension(unsigned char* buffer, unsigned short len) {
    unsigned short versions_len = buffer[0];
    assert(versions_len % 2 == 0 && versions_len >= 2);
    assert(versions_len <= len-1);

    for (int i = 1; i<len; i+=2) {
        if (htons(*(short*)&(buffer[i])) == 0x0304) return 0; // supports TLS 1.3
    }
    return 1;
}

Vector parse_extension_lenshort_mod2_generic(unsigned char * buffer, unsigned short len) {
    Vector out = {0};
    out.len = htons(*(unsigned short*)buffer);
    assert((out.len %2) == 0 && out.len <= len-2 && out.len >= 2);
    out.data = malloc(out.len);
    assert(out.data != NULL);
    memcpy(out.data, buffer+2, out.len);
    return out;
}

Vector parse_supported_groups_extension(unsigned char *buffer, unsigned short len) {
    return parse_extension_lenshort_mod2_generic(buffer, len);
}

Vector parse_signature_algorithms_extensions(unsigned char * buffer, unsigned short len) {
    return parse_extension_lenshort_mod2_generic(buffer, len);
}