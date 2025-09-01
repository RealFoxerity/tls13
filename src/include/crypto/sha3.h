#ifndef SHA384_H
#define SHA384_H

#include <stddef.h>
#define SHA384_BYTE_SIZE 48

void sha3_384_hash(char * hash_out, char * input, size_t input_len);

#endif