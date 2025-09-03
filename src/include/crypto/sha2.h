#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>
#include <stdlib.h>

typedef unsigned __int128 uint128_t;

#define SHA1_HASH_BYTES  (160/8)
#define SHA224_HASH_BYTES  (224/8)
#define SHA256_HASH_BYTES  (256/8)
#define SHA384_HASH_BYTES  (384/8)
#define SHA512_HASH_BYTES  (512/8)
#define SHA512_224_HASH_BYTES  (224/8)
#define SHA512_256_HASH_BYTES  (256/8)

void sha1_sum      (unsigned char * hash_out, const unsigned char * input, uint64_t input_len);
void sha224_sum    (unsigned char * hash_out, const unsigned char * input, uint64_t input_len);
void sha256_sum    (unsigned char * hash_out, const unsigned char * input, uint64_t input_len);
void sha384_sum    (unsigned char * hash_out, const unsigned char * input, uint128_t input_len);
void sha512_sum    (unsigned char * hash_out, const unsigned char * input, uint128_t input_len);
void sha512_224_sum(unsigned char * hash_out, const unsigned char * input, uint128_t input_len);
void sha512_256_sum(unsigned char * hash_out, const unsigned char * input, uint128_t input_len);

#endif