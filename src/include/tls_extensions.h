#ifndef TLS_EXTENSIONS_H
#define TLS_EXTENSIONS_H
#include "tls.h"

char* parse_server_name_extension(unsigned char* buffer, unsigned short len);
int parse_supported_versions_extension(unsigned char* buffer, unsigned short len);
Vector parse_supported_groups_extension(unsigned char *buffer, unsigned short len);

#endif