#ifndef SHA384_H
#define SHA384_H

#include <stddef.h>

#define SHA3_224_HASH_BYTES  (224/8)
#define SHA3_256_HASH_BYTES  (256/8)
#define SHA3_384_HASH_BYTES  (384/8)
#define SHA3_512_HASH_BYTES  (512/8)

void sha3_224_sum(unsigned char * hash_out, const unsigned char * input, int input_len);
void sha3_256_sum(unsigned char * hash_out, const unsigned char * input, int input_len);
void sha3_384_sum(unsigned char * hash_out, const unsigned char * input, int input_len);
void sha3_512_sum(unsigned char * hash_out, const unsigned char * input, int input_len);

#endif