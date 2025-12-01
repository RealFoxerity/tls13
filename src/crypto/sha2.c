// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// note 1: page 5(10) Bitwise complement operation is "not", operator ~
// note 2: Addition modulo 2^w is just normal addition in C, since the number rolls around
#include <endian.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "../include/crypto/sha2_internal.h"
#include <assert.h>
#include <string.h>
// sha-1, sha-224, sha-256, sha-384, sha-512, sha-512/224, sha-512/256

// TODO: sha2 uses big endian, this code works on my LE machine, i don't have any big endian machines, not tested for functionality - test in a vm?

// NOTE: We use size_t, however, sha1 and sha2-128 - sha2-256 require uint64_t and sha2-384 onwards requires uint128_t, 
// but considering there is absolutely no way we get even close to those values, using standard variables is (probably) better

// TODO: rewrite sha-1 to be a running hash
// TODO: think about lessening the stack thrashing

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#warning "This sha2 implementation is untested on big endian"
#endif

#ifndef __SIZEOF_INT128__
#error "Cannot compile on platform without 128bit wide ints"
#endif


static inline uint128_t htobe128(uint128_t x) {
    uint128_t orig_x = x;
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ // no clue if works tbh
    ((uint64_t*)(&x))[0] = htobe64((uint64_t)(orig_x>>(sizeof(uint128_t)*8/2)));
    ((uint64_t*)(&x))[1] = htobe64((uint64_t)orig_x);
    #else 
    ((uint64_t*)(&x))[1] = htobe64((uint64_t)(orig_x>>(sizeof(uint128_t)*8/2)));
    ((uint64_t*)(&x))[0] = htobe64((uint64_t)orig_x);
    #endif
    return x;
}

static inline uint64_t sha2_rotl_64(int n, uint64_t x) { // potentially replacable with __builtin_stdc_rotate_left
    return (x<<n) | (x>>((sizeof(uint64_t)*8)-n));
}

static inline uint64_t sha2_rotr_64(int n, uint64_t x) { // potentially replacable with __builtin_stdc_rotate_right
    return (x>>n) | (x<<((sizeof(uint64_t)*8)-n));
}

static inline uint32_t sha2_rotl_32(int n, uint32_t x) {
    return (x<<n) | (x>>((sizeof(uint32_t)*8)-n));
}

static inline uint32_t sha2_rotr_32(int n, uint32_t x) {
    return (x>>n) | (x<<((sizeof(uint32_t)*8)-n));
}

#define sha2_shr(n, x) ((x)>>(n)) // to keep naming convention

// func numbers correspond to numbers next to the equations in the standards

static inline uint32_t sha1_f(uint32_t x, uint32_t y, uint32_t z, char t) {
    assert(t <= 79);

    if (t <= 19) {
        return (x & y) ^ ((~x)&z);
    } else if (t <= 39) {
        return x ^ y ^ z;
    } else if (t <= 59) {
        return (x & y) ^ (x & z) ^ (y & z);
    } else if (t <= 79) {
        return x ^ y ^ z;
    }
    __builtin_unreachable();
} 

static inline uint32_t sha256_Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}
static inline uint32_t sha256_Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sha256_sigma0(uint32_t x) { // is it sigma notation or not???????
    return sha2_rotr_32(2, x) ^ sha2_rotr_32(13, x) ^ sha2_rotr_32(22, x);
}
static inline uint32_t sha256_sigma1(uint32_t x) {
    return sha2_rotr_32(6, x) ^ sha2_rotr_32(11, x) ^ sha2_rotr_32(25, x);
}

static inline uint32_t sha256_lsigma0(uint32_t x) {
    return sha2_rotr_32(7, x) ^ sha2_rotr_32(18, x) ^ sha2_shr(3, x);
}
static inline uint32_t sha256_lsigma1(uint32_t x) {
    return sha2_rotr_32(17, x) ^ sha2_rotr_32(19, x) ^ sha2_shr(10, x);
}



static inline uint64_t sha512_Ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ ((~x) & z);
}
static inline uint64_t sha512_Maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint64_t sha512_sigma0(uint64_t x) {
    return sha2_rotr_64(28, x) ^ sha2_rotr_64(34, x) ^ sha2_rotr_64(39, x);
}
static inline uint64_t sha512_sigma1(uint64_t x) {
    return sha2_rotr_64(14, x) ^ sha2_rotr_64(18, x) ^ sha2_rotr_64(41, x);
}

static inline uint64_t sha512_lsigma0(uint64_t x) {
    return sha2_rotr_64(1, x) ^ sha2_rotr_64(8, x) ^ sha2_shr(7, x);
}
static inline uint64_t sha512_lsigma1(uint64_t x) {
    return sha2_rotr_64(19, x) ^ sha2_rotr_64(61, x) ^ sha2_shr(6, x);
}

// only used by sha1 since it's still not a running hash
static size_t sha2_pad(char ** input, size_t input_len, int block_size_bits) { // NOTE: the input_len and new_size *should* be uint128_t according to fips, but since that uses bits and we bytes and since there is no way someone hashes 2^64 bytes of data, i think we're safe
    assert(block_size_bits == SHA256_MESSAGE_BLOCK || block_size_bits == SHA512_MESSAGE_BLOCK);
    size_t new_size = input_len + 1 + ((block_size_bits == SHA256_MESSAGE_BLOCK)?sizeof(uint64_t):sizeof(uint128_t)); // +1 for added bit and since we always operate on bytes, it is safe to assume it will take up a whole byte, see page 13(18)
    new_size = new_size + (block_size_bits / 8 - (new_size%(block_size_bits/8)));
    *input = realloc(*input, new_size);
    
    assert(new_size-input_len >= 1 + (block_size_bits == SHA256_MESSAGE_BLOCK?sizeof(uint64_t):sizeof(uint128_t)));

    memset((*input)+input_len, 0, new_size-input_len);

    (*input)[input_len] = 0b10000000;

    switch (block_size_bits) {
        case SHA256_MESSAGE_BLOCK:
            *(uint64_t*) ((*input) + new_size - sizeof(uint64_t))  = htobe64((uint64_t)(input_len*8)); // fips180 dictates to be a big endian size of message in bits
            break;
        case SHA512_MESSAGE_BLOCK:
            *(uint128_t*)((*input) + new_size - sizeof(uint128_t)) = htobe128((uint128_t)(input_len*8));
        default: break; // should never happen
    }
    return new_size;
}

void sha1_sum(unsigned char * hash_out, const unsigned char * input, size_t input_len) {
    uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, temp = 0;
    uint32_t message_schedule[SHA1_MESSAGE_SCHED_LEN] = {0};

    uint32_t * new_input = calloc(input_len, 1);
    assert(new_input);
    memcpy(new_input, input, input_len);

    input_len = sha2_pad((char **)&new_input, input_len, SHA256_MESSAGE_BLOCK);
    uint32_t hash_values[input_len/(SHA1_MESSAGE_SCHED_LEN/8) + 1][SHA1_WORK_VARS];
    memset(hash_values, 0, sizeof(hash_values));
    memcpy(hash_values[0], sha1_iv, sizeof(sha1_iv));

    for (int i = 0; i < input_len/(SHA256_MESSAGE_BLOCK/8); i++) {
        memset(message_schedule, 0, sizeof(message_schedule));
        for (int t = 0; t < SHA1_MESSAGE_SCHED_LEN; t++) {
            if (t <= 15) {
                message_schedule[t] = be32toh(new_input[(SHA256_MESSAGE_BLOCK/8)*i/sizeof(uint32_t)+t]);
            } else {
                message_schedule[t] = sha2_rotl_32(1, message_schedule[t-3] ^ message_schedule[t-8] ^ message_schedule[t-14] ^ message_schedule[t-16]);
            }
        }

        a = hash_values[i][0];
        b = hash_values[i][1];
        c = hash_values[i][2];
        d = hash_values[i][3];
        e = hash_values[i][4];
        for (int t = 0; t < SHA1_MESSAGE_SCHED_LEN; t++) {
            temp = sha2_rotl_32(5, a) + sha1_f(b, c, d, t) + e + GET_SHA1_CONST(t) + message_schedule[t];
            e = d;
            d = c;
            c = sha2_rotl_32(30, b);
            b = a;
            a = temp;

        }
        hash_values[i+1][0] = a + hash_values[i][0];
        hash_values[i+1][1] = b + hash_values[i][1];
        hash_values[i+1][2] = c + hash_values[i][2];
        hash_values[i+1][3] = d + hash_values[i][3];
        hash_values[i+1][4] = e + hash_values[i][4];
    }
    free(new_input);
    for (int t = 0; t < 5; t++) {
        hash_values[input_len/(SHA256_MESSAGE_BLOCK/8)][t] = be32toh(hash_values[input_len/(SHA256_MESSAGE_BLOCK/8)][t]);
    }
    memcpy(hash_out, hash_values[input_len/(SHA256_MESSAGE_BLOCK/8)], sizeof(sha1_iv));
}

extern void sha256_update_internal(sha2_ctx_t * ctx, const unsigned char * input, size_t input_len, const uint32_t * iv);
extern void sha512_update_internal(sha2_ctx_t * ctx, const unsigned char * input, size_t input_len, const uint64_t * iv);
void sha2_pad_block(sha2_ctx_t * ctx, int block_size_bits, void * iv) {
    assert(ctx);
    assert(block_size_bits == SHA256_MESSAGE_BLOCK || block_size_bits == SHA512_MESSAGE_BLOCK);
    assert(ctx->sha256.temp_buf_end < block_size_bits / 8); // this is why we need temp_buf_end as a first element

    size_t pad_size = 0;
    uint8_t * pad_data = NULL;

    switch (block_size_bits) {
        case SHA256_MESSAGE_BLOCK:
            pad_size = ctx->sha256.computed_bytes + 1 + sizeof(uint64_t); // +1 for added bit and since we always operate on bytes, it is safe to assume it will take up a whole byte, see page 13(18)
            pad_size = pad_size + (block_size_bits / 8 - (pad_size%(block_size_bits/8)));
            pad_size -= ctx->sha256.computed_bytes;
            assert(pad_size >= 1 + sizeof(uint64_t));

            pad_data = calloc(pad_size, 1);
            pad_data[0] = 0x80;

            *(uint64_t *)&pad_data[pad_size - sizeof(uint64_t)] = htobe64(ctx->sha256.computed_bytes*8);

            sha256_update_internal(ctx, pad_data, pad_size, iv);
            break;
        case SHA512_MESSAGE_BLOCK:
            pad_size = ctx->sha512.computed_bytes + 1 + sizeof(uint128_t); // +1 for added bit and since we always operate on bytes, it is safe to assume it will take up a whole byte, see page 13(18)
            pad_size = pad_size + (block_size_bits / 8 - (pad_size%(block_size_bits/8)));
            pad_size -= ctx->sha512.computed_bytes;
            assert(pad_size >= 1 + sizeof(uint128_t));

            pad_data = calloc(pad_size, 1);
            pad_data[0] = 0x80;

            *(uint128_t *)&pad_data[pad_size - sizeof(uint128_t)] = htobe128(ctx->sha512.computed_bytes*8);

            sha512_update_internal(ctx, pad_data, pad_size, iv);
            break;
    }
    free(pad_data);
}

void sha256_init_internal(sha2_ctx_t * ctx, const uint32_t * iv) {
    memset(ctx, 0, sizeof(sha2_ctx_t));
    memcpy(ctx->sha256.work_vars, iv, sizeof(uint32_t)*SHA256_WORK_VARS);
}
void sha256_update_internal(sha2_ctx_t * ctx, const unsigned char * input, size_t input_len, const uint32_t * iv) { // work on a single block at a time so that we don't have to store all of the data at once 
    ctx->sha256.computed_bytes += input_len;

    if (ctx->sha256.temp_buf_end + input_len < SHA256_MESSAGE_BLOCK/8) {
        memcpy(&ctx->sha256.temp_buf[ctx->sha256.temp_buf_end], input, input_len);
        ctx->sha256.temp_buf_end += input_len;
        return;
    }
    
    uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0, temp1 = 0, temp2 = 0;
    uint32_t message_schedule[SHA256_MESSAGE_SCHED_LEN] = {0};

    memcpy(&ctx->sha256.temp_buf[ctx->sha256.temp_buf_end], input, SHA256_MESSAGE_BLOCK/8  - ctx->sha256.temp_buf_end);
    input_len -= SHA256_MESSAGE_BLOCK/8  - ctx->sha256.temp_buf_end;
    input += SHA256_MESSAGE_BLOCK/8  - ctx->sha256.temp_buf_end;
    size_t chunks = 1 + input_len/SHA256_MESSAGE_BLOCK/8;

    for (size_t i = 0; i < chunks; i++) {
        memset(message_schedule, 0, sizeof(message_schedule));
        for (int t = 0; t < SHA256_MESSAGE_SCHED_LEN; t++) {
            if (t <= 15) {
                message_schedule[t] = be32toh(((uint32_t*)ctx->sha256.temp_buf)[t]);
            } else {
                message_schedule[t] = sha256_lsigma1(message_schedule[t-2]) + message_schedule[t-7] + sha256_lsigma0(message_schedule[t-15]) + message_schedule[t-16];
            }
        }
        a = ctx->sha256.work_vars[0];
        b = ctx->sha256.work_vars[1];
        c = ctx->sha256.work_vars[2];
        d = ctx->sha256.work_vars[3];
        e = ctx->sha256.work_vars[4];
        f = ctx->sha256.work_vars[5];
        g = ctx->sha256.work_vars[6];
        h = ctx->sha256.work_vars[7];

        for (int t = 0; t < SHA256_MESSAGE_SCHED_LEN; t++) {
            temp1 = h + sha256_sigma1(e) + sha256_Ch(e, f, g) + sha256_consts[t] + message_schedule[t];
            temp2 = sha256_sigma0(a) + sha256_Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        ctx->sha256.work_vars[0] += a;
        ctx->sha256.work_vars[1] += b;
        ctx->sha256.work_vars[2] += c;
        ctx->sha256.work_vars[3] += d;
        ctx->sha256.work_vars[4] += e;
        ctx->sha256.work_vars[5] += f;
        ctx->sha256.work_vars[6] += g;
        ctx->sha256.work_vars[7] += h;

        if (i != chunks - 1) {
            memcpy(&ctx->sha256.temp_buf, &input[(i-1)*SHA256_MESSAGE_BLOCK/8], SHA256_MESSAGE_BLOCK/8);
        } else {
            memcpy(&ctx->sha256.temp_buf, &input[i*SHA256_MESSAGE_BLOCK/8], input_len % (SHA256_MESSAGE_BLOCK / 8));
            ctx->sha256.temp_buf_end = input_len % (SHA256_MESSAGE_BLOCK / 8);
        }
    }
}

void sha256_finalize_internal(sha2_ctx_t * ctx, unsigned char * hash_out, int hash_vars, const uint32_t * iv) {
    sha2_ctx_t temp_ctx = *ctx;

    sha2_pad_block(&temp_ctx, SHA256_MESSAGE_BLOCK, (void*)iv);

    for (int t = 0; t < SHA256_WORK_VARS; t++) {
        temp_ctx.sha256.work_vars[t] = be32toh(temp_ctx.sha256.work_vars[t]);
    }

    memcpy(hash_out, temp_ctx.sha256.work_vars, sizeof(uint32_t)*hash_vars);
}

void sha512_init_internal(sha2_ctx_t * ctx, const uint64_t * iv) {
    memset(ctx, 0, sizeof(sha2_ctx_t));
    memcpy(ctx->sha512.work_vars, iv, sizeof(uint64_t)*SHA512_WORK_VARS);
}
void sha512_update_internal(sha2_ctx_t * ctx, const unsigned char * input, size_t input_len, const uint64_t * iv) {
    ctx->sha512.computed_bytes += input_len;

    if (ctx->sha512.temp_buf_end + input_len < SHA512_MESSAGE_BLOCK/8) {
        memcpy(&ctx->sha512.temp_buf[ctx->sha512.temp_buf_end], input, input_len);
        ctx->sha512.temp_buf_end += input_len;
        return;
    }
    
    uint64_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0, temp1 = 0, temp2 = 0;
    uint64_t message_schedule[SHA512_MESSAGE_SCHED_LEN] = {0};

    memcpy(&ctx->sha512.temp_buf[ctx->sha512.temp_buf_end], input, SHA512_MESSAGE_BLOCK/8  - ctx->sha512.temp_buf_end);
    input_len -= SHA512_MESSAGE_BLOCK/8  - ctx->sha512.temp_buf_end;
    input += SHA512_MESSAGE_BLOCK/8  - ctx->sha512.temp_buf_end;
    size_t chunks = 1 + input_len/SHA512_MESSAGE_BLOCK/8;

    for (size_t i = 0; i < chunks; i++) {
        memset(message_schedule, 0, sizeof(message_schedule));
        for (int t = 0; t < SHA512_MESSAGE_SCHED_LEN; t++) {
            if (t <= 15) {
                message_schedule[t] = be64toh(((uint64_t*)ctx->sha512.temp_buf)[t]);
            } else {
                message_schedule[t] = sha512_lsigma1(message_schedule[t-2]) + message_schedule[t-7] + sha512_lsigma0(message_schedule[t-15]) + message_schedule[t-16];
            }
        }
        a = ctx->sha512.work_vars[0];
        b = ctx->sha512.work_vars[1];
        c = ctx->sha512.work_vars[2];
        d = ctx->sha512.work_vars[3];
        e = ctx->sha512.work_vars[4];
        f = ctx->sha512.work_vars[5];
        g = ctx->sha512.work_vars[6];
        h = ctx->sha512.work_vars[7];

        for (int t = 0; t < SHA512_MESSAGE_SCHED_LEN; t++) {
            temp1 = h + sha512_sigma1(e) + sha512_Ch(e, f, g) + sha512_consts[t] + message_schedule[t];
            temp2 = sha512_sigma0(a) + sha512_Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        ctx->sha512.work_vars[0] += a;
        ctx->sha512.work_vars[1] += b;
        ctx->sha512.work_vars[2] += c;
        ctx->sha512.work_vars[3] += d;
        ctx->sha512.work_vars[4] += e;
        ctx->sha512.work_vars[5] += f;
        ctx->sha512.work_vars[6] += g;
        ctx->sha512.work_vars[7] += h;

        if (i != chunks - 1) {
            memcpy(&ctx->sha512.temp_buf, &input[(i-1)*SHA512_MESSAGE_BLOCK/8], SHA512_MESSAGE_BLOCK/8);
        } else {
            memcpy(&ctx->sha512.temp_buf, &input[i*SHA512_MESSAGE_BLOCK/8], input_len % (SHA512_MESSAGE_BLOCK / 8));
            ctx->sha512.temp_buf_end = input_len % (SHA512_MESSAGE_BLOCK / 8);
        }
    }
}

void sha512_finalize_internal(sha2_ctx_t * ctx, unsigned char * hash_out, int hash_vars, const uint64_t * iv) {
    sha2_ctx_t temp_ctx = *ctx;

    sha2_pad_block(&temp_ctx, SHA512_MESSAGE_BLOCK, (void*) iv);

    for (int t = 0; t < SHA512_WORK_VARS; t++) {
        temp_ctx.sha512.work_vars[t] = be64toh(temp_ctx.sha512.work_vars[t]);
    }

    memcpy(hash_out, temp_ctx.sha512.work_vars, sizeof(uint64_t)*hash_vars);
}