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


#define SHA1_MESSAGE_SCHED_LEN 80
#define SHA1_WORK_VARS 5

#define SHA256_MESSAGE_SCHED_LEN 64
#define SHA256_WORK_VARS 8 // a - h
#define SHA224_WORK_VARS 7

#define SHA512_MESSAGE_SCHED_LEN 80
#define SHA512_WORK_VARS 8
#define SHA384_WORK_VARS 7

#define SHA256_MESSAGE_BLOCK (512)
#define SHA512_MESSAGE_BLOCK (1024)

union sha2_ctx {
    struct {
        int temp_buf_end; // leave as the first element
        size_t computed_bytes;
        uint8_t temp_buf[SHA512_MESSAGE_BLOCK/8];
        uint64_t work_vars[SHA512_WORK_VARS];
    } sha512;
    struct sha256_ctx {
        int temp_buf_end;
        size_t computed_bytes; // for the pad
        uint8_t temp_buf[SHA256_MESSAGE_BLOCK/8];
        uint32_t work_vars[SHA256_WORK_VARS];
    } sha256;
} typedef sha2_ctx_t;

// TODO: finish running hash for sha1
void sha224_init    (sha2_ctx_t * ctx);
void sha224_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len);
void sha224_finalize(sha2_ctx_t * ctx, unsigned char * hash_out);

void sha256_init    (sha2_ctx_t * ctx);
void sha256_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len);
void sha256_finalize(sha2_ctx_t * ctx, unsigned char * hash_out);

void sha384_init    (sha2_ctx_t * ctx);
void sha384_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len);
void sha384_finalize(sha2_ctx_t * ctx, unsigned char * hash_out);

void sha512_init    (sha2_ctx_t * ctx);
void sha512_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len);
void sha512_finalize(sha2_ctx_t * ctx, unsigned char * hash_out);

void sha512_224_init    (sha2_ctx_t * ctx);
void sha512_224_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len);
void sha512_224_finalize(sha2_ctx_t * ctx, unsigned char * hash_out);

void sha512_256_init    (sha2_ctx_t * ctx);
void sha512_256_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len);
void sha512_256_finalize(sha2_ctx_t * ctx, unsigned char * hash_out);

void sha1_sum      (unsigned char * hash_out, const unsigned char * input, size_t input_len);
void sha224_sum    (unsigned char * hash_out, const unsigned char * input, size_t input_len); // wrapped around init, update, finalize
void sha256_sum    (unsigned char * hash_out, const unsigned char * input, size_t input_len); // wrapped around init, update, finalize
void sha384_sum    (unsigned char * hash_out, const unsigned char * input, size_t input_len); // wrapped around init, update, finalize
void sha512_sum    (unsigned char * hash_out, const unsigned char * input, size_t input_len); // wrapped around init, update, finalize
void sha512_224_sum(unsigned char * hash_out, const unsigned char * input, size_t input_len); // wrapped around init, update, finalize
void sha512_256_sum(unsigned char * hash_out, const unsigned char * input, size_t input_len); // wrapped around init, update, finalize

#endif