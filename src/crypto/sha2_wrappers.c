#include "include/sha2_internal.h"
#include <string.h>

extern void sha256_init_internal(sha2_ctx_t * ctx, const uint32_t * iv);
extern void sha256_update_internal(sha2_ctx_t * ctx, const unsigned char * input, size_t input_len, const uint32_t * iv);
extern void sha256_finalize_internal(sha2_ctx_t * ctx, unsigned char * hash_out, int hash_vars, const uint32_t * iv);

extern void sha512_init_internal(sha2_ctx_t * ctx, const uint64_t * iv);
extern void sha512_update_internal(sha2_ctx_t * ctx, const unsigned char * input, size_t input_len, const uint64_t * iv);
extern void sha512_finalize_internal(sha2_ctx_t * ctx, unsigned char * hash_out, int hash_vars, const uint64_t * iv);

extern const uint64_t sha512_iv[];
extern const uint64_t sha512_224_iv[];
extern const uint64_t sha512_256_iv[];
extern const uint64_t sha384_iv[];
extern const uint32_t sha256_iv[];


void sha224_init    (sha2_ctx_t * ctx) {sha256_init_internal(ctx, sha224_iv);}
void sha224_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len) {sha256_update_internal(ctx, input, input_len, sha224_iv);}
void sha224_finalize(sha2_ctx_t * ctx, unsigned char * hash_out) {sha256_finalize_internal(ctx, hash_out, SHA224_WORK_VARS, sha224_iv);}

void sha256_init    (sha2_ctx_t * ctx) {sha256_init_internal(ctx, sha256_iv);}
void sha256_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len) {sha256_update_internal(ctx, input, input_len, sha256_iv);}
void sha256_finalize(sha2_ctx_t * ctx, unsigned char * hash_out) {sha256_finalize_internal(ctx, hash_out, SHA256_WORK_VARS, sha256_iv);}

void sha384_init    (sha2_ctx_t * ctx) {sha512_init_internal(ctx, sha384_iv);}
void sha384_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len) {sha512_update_internal(ctx, input, input_len, sha384_iv);}
void sha384_finalize(sha2_ctx_t * ctx, unsigned char * hash_out) {sha512_finalize_internal(ctx, hash_out, SHA384_WORK_VARS, sha384_iv);}

void sha512_init    (sha2_ctx_t * ctx) {sha512_init_internal(ctx, sha512_iv);}
void sha512_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len) {sha512_update_internal(ctx, input, input_len, sha512_iv);}
void sha512_finalize(sha2_ctx_t * ctx, unsigned char * hash_out) {sha512_finalize_internal(ctx, hash_out, SHA512_WORK_VARS, sha512_iv);}

void sha512_224_init    (sha2_ctx_t * ctx) {sha512_init_internal(ctx, sha512_224_iv);}
void sha512_224_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len) {sha512_update_internal(ctx, input, input_len, sha512_224_iv);}
void sha512_224_finalize(sha2_ctx_t * ctx, unsigned char * hash_out) { // sha512_t is just a truncation (and a different iv)
    unsigned char temp_hash[SHA512_HASH_BYTES];
    sha512_finalize_internal(ctx, temp_hash, SHA512_WORK_VARS, sha512_224_iv);
    memcpy(hash_out, temp_hash, SHA512_224_HASH_BYTES);
}

void sha512_256_init    (sha2_ctx_t * ctx) {sha512_init_internal(ctx, sha512_256_iv);}
void sha512_256_update  (sha2_ctx_t * ctx, const unsigned char * input, size_t input_len) {sha512_update_internal(ctx, input, input_len, sha512_256_iv);}
void sha512_256_finalize(sha2_ctx_t * ctx, unsigned char * hash_out) {
    unsigned char temp_hash[SHA512_HASH_BYTES];
    sha512_finalize_internal(ctx, temp_hash, SHA512_WORK_VARS, sha512_256_iv);
    memcpy(hash_out, temp_hash, SHA512_256_HASH_BYTES);
}

void sha224_sum(unsigned char * hash_out, const unsigned char * input, size_t input_len) {
    sha2_ctx_t context;
    sha224_init(&context);
    sha224_update(&context, input, input_len);
    sha224_finalize(&context, hash_out);
}

void sha256_sum(unsigned char * hash_out, const unsigned char * input, size_t input_len) {
    sha2_ctx_t context;
    sha256_init(&context);
    sha256_update(&context, input, input_len);
    sha256_finalize(&context, hash_out);
}

void sha384_sum(unsigned char * hash_out, const unsigned char * input, size_t input_len) {
    sha2_ctx_t context;
    sha384_init(&context);
    sha384_update(&context, input, input_len);
    sha384_finalize(&context, hash_out);
}

void sha512_sum(unsigned char * hash_out, const unsigned char * input, size_t input_len) {
    sha2_ctx_t context;
    sha512_init(&context);
    sha512_update(&context, input, input_len);
    sha512_finalize(&context, hash_out);
}


// NOTE: FIPS 180 does include a function to generate these IVs based on _t, however since others aren't officially 
// approved and FIPS 180 also includes the IVs for these, i chose to ignore the function, see page 16(21) - 17 (22)
void sha512_224_sum(unsigned char * hash_out, const unsigned char * input, size_t input_len) {
    sha2_ctx_t context;
    sha512_224_init(&context);
    sha512_224_update(&context, input, input_len);
    sha512_224_finalize(&context, hash_out);
}
void sha512_256_sum(unsigned char * hash_out, const unsigned char * input, size_t input_len) {
    sha2_ctx_t context;
    sha512_256_init(&context);
    sha512_256_update(&context, input, input_len);
    sha512_256_finalize(&context, hash_out);
}