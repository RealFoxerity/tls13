// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// note 1: page 5(10) Bitwise complement operation is "not", operator ~
// note 2: Addition modulo 2^w is just normal addition in C, since the number rolls around
#include <endian.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "../include/crypto/sha2.h"
#include <assert.h>
#include <string.h>
// sha-1, sha-224, sha-256, sha-384, sha-512, sha-512/224, sha-512/256

// TODO: sha2 uses big endian, this code works on my LE machine, i don't have any big endian machines, not tested for functionality - test in a vm?

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

const static uint32_t sha1_consts[] = {
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};
#define GET_SHA1_CONST(t) (sha1_consts[(t)/20])

const static uint32_t sha256_consts[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

const static uint64_t sha512_consts[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

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


#define SHA256_MESSAGE_BLOCK (512)
#define SHA512_MESSAGE_BLOCK (1024)
// TODO: create running hash
// TODO: rewrite functions to only pad the last block 

static uint128_t sha2_pad(char ** input, size_t input_len, int block_size_bits) { // NOTE: the input_len and new_size *should* be uint128_t according to fips, but since that uses bits and we bytes and since there is no way someone hashes 2^64 bytes of data, i think we're safe
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


#define SHA1_MESSAGE_SCHED_LEN 80
#define SHA1_WORK_VARS 5

const uint32_t sha1_iv[SHA1_WORK_VARS] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0,
};

void sha1_sum(unsigned char * hash_out, const unsigned char * input, uint64_t input_len) {
    uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, temp = 0;
    uint32_t message_schedule[SHA1_MESSAGE_SCHED_LEN] = {0};

    uint32_t * new_input = malloc(input_len);
    assert(new_input);
    memset(new_input, 0, input_len);
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

#define SHA256_MESSAGE_SCHED_LEN 64
#define SHA256_WORK_VARS 8

const uint32_t sha256_iv[SHA256_WORK_VARS] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

const uint32_t sha224_iv[SHA256_WORK_VARS] = {
    0xc1059ed8,
    0x367cd507,
    0x3070dd17,
    0xf70e5939,
    0xffc00b31,
    0x68581511,
    0x64f98fa7,
    0xbefa4fa4
};

static void sha256_sum_internal(unsigned char * hash_out, int hash_vars, const unsigned char * input, uint64_t input_len, const uint32_t* iv) {
    uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0, temp1 = 0, temp2 = 0;
    uint32_t message_schedule[SHA256_MESSAGE_SCHED_LEN] = {0};

    uint32_t * new_input = malloc(input_len);
    assert(new_input);
    memset(new_input, 0, input_len);
    memcpy(new_input, input, input_len);

    input_len = sha2_pad((char **)&new_input, input_len, SHA256_MESSAGE_BLOCK);
    
    uint32_t hash_values[input_len/(SHA256_MESSAGE_SCHED_LEN/8) + 1][SHA256_WORK_VARS];

    memset(hash_values, 0, sizeof(hash_values));
    memcpy(hash_values[0], iv, SHA256_WORK_VARS*sizeof(uint32_t));



    for (int i = 0; i < input_len/(SHA256_MESSAGE_BLOCK/8); i++) {
        memset(message_schedule, 0, sizeof(message_schedule));
        for (int t = 0; t < SHA256_MESSAGE_SCHED_LEN; t++) {
            if (t <= 15) {
                message_schedule[t] = be32toh(new_input[(SHA256_MESSAGE_BLOCK/8)*i/sizeof(uint32_t)+t]);
            } else {
                message_schedule[t] = sha256_lsigma1(message_schedule[t-2]) + message_schedule[t-7] + sha256_lsigma0(message_schedule[t-15]) + message_schedule[t-16];
            }
        }
        a = hash_values[i][0];
        b = hash_values[i][1];
        c = hash_values[i][2];
        d = hash_values[i][3];
        e = hash_values[i][4];
        f = hash_values[i][5];
        g = hash_values[i][6];
        h = hash_values[i][7];

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
        hash_values[i+1][0] = a + hash_values[i][0];
        hash_values[i+1][1] = b + hash_values[i][1];
        hash_values[i+1][2] = c + hash_values[i][2];
        hash_values[i+1][3] = d + hash_values[i][3];
        hash_values[i+1][4] = e + hash_values[i][4];
        hash_values[i+1][5] = f + hash_values[i][5];
        hash_values[i+1][6] = g + hash_values[i][6];
        hash_values[i+1][7] = h + hash_values[i][7];
    }
    free(new_input);
    for (int t = 0; t < hash_vars; t++) {
        hash_values[input_len/(SHA256_MESSAGE_BLOCK/8)][t] = be32toh(hash_values[input_len/(SHA256_MESSAGE_BLOCK/8)][t]);
    }
    memcpy(hash_out, hash_values[input_len/(SHA256_MESSAGE_BLOCK/8)], sizeof(uint32_t)*hash_vars);
}

void sha256_sum(unsigned char * hash_out, const unsigned char * input, uint64_t input_len) {
    sha256_sum_internal(hash_out, 8, input, input_len, sha256_iv);
}

void sha224_sum(unsigned char * hash_out, const unsigned char * input, uint64_t input_len) {
    sha256_sum_internal(hash_out, 7,  input, input_len, sha224_iv);
}

#define SHA512_MESSAGE_SCHED_LEN 80
#define SHA512_WORK_VARS 8
const uint64_t sha512_iv[SHA512_WORK_VARS] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0X510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
};

const uint64_t sha384_iv[SHA512_WORK_VARS] = {
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4
};

const uint64_t sha512_224_iv[SHA512_WORK_VARS] = {
    0x8C3D37C819544DA2,
    0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82,
    0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8,
    0x77E36F7304C48942,
    0x3F9D85A86A1D36C8,
    0x1112E6AD91D692A1,
};

const uint64_t sha512_256_iv[SHA512_WORK_VARS] = {
    0x22312194FC2BF72C,
    0x9F555FA3C84C64C2,
    0x2393B86B6F53B151,
    0x963877195940EABD,
    0x96283EE2A88EFFE3,
    0xBE5E1E2553863992,
    0x2B0199FC2C85B8AA,
    0x0EB72DDC81C52CA2
};

void sha512_sum_internal(unsigned char * hash_out, int hash_len, const unsigned char * input, uint128_t input_len, const uint64_t* iv) {
    uint64_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0, temp1 = 0, temp2 = 0;
    uint64_t message_schedule[SHA512_MESSAGE_SCHED_LEN] = {0};

    uint64_t * new_input = malloc(input_len);
    assert(new_input);
    memset(new_input, 0, input_len);
    memcpy(new_input, input, input_len);

    input_len = sha2_pad((char **)&new_input, input_len, SHA512_MESSAGE_BLOCK);
    
    uint64_t hash_values[input_len/(SHA512_MESSAGE_SCHED_LEN/8) + 1][SHA512_WORK_VARS];

    memset(hash_values, 0, sizeof(hash_values));
    memcpy(hash_values[0], iv, SHA512_WORK_VARS*sizeof(uint64_t));

    for (int i = 0; i < input_len/(SHA512_MESSAGE_BLOCK/8); i++) {
        memset(message_schedule, 0, sizeof(message_schedule));
        for (int t = 0; t < SHA512_MESSAGE_SCHED_LEN; t++) {
            if (t <= 15) {
                message_schedule[t] = be64toh(new_input[(SHA512_MESSAGE_BLOCK/8)*i/sizeof(uint64_t)+t]);
            } else {
                message_schedule[t] = sha512_lsigma1(message_schedule[t-2]) + message_schedule[t-7] + sha512_lsigma0(message_schedule[t-15]) + message_schedule[t-16];
            }
        }
        a = hash_values[i][0];
        b = hash_values[i][1];
        c = hash_values[i][2];
        d = hash_values[i][3];
        e = hash_values[i][4];
        f = hash_values[i][5];
        g = hash_values[i][6];
        h = hash_values[i][7];

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
        hash_values[i+1][0] = a + hash_values[i][0];
        hash_values[i+1][1] = b + hash_values[i][1];
        hash_values[i+1][2] = c + hash_values[i][2];
        hash_values[i+1][3] = d + hash_values[i][3];
        hash_values[i+1][4] = e + hash_values[i][4];
        hash_values[i+1][5] = f + hash_values[i][5];
        hash_values[i+1][6] = g + hash_values[i][6];
        hash_values[i+1][7] = h + hash_values[i][7];
    }
    free(new_input);
    for (int t = 0; t < SHA512_WORK_VARS; t++) {
        hash_values[input_len/(SHA512_MESSAGE_BLOCK/8)][t] = htobe64(hash_values[input_len/(SHA512_MESSAGE_BLOCK/8)][t]);
    }
    //memcpy(hash_out, hash_values[input_len/(SHA512_MESSAGE_BLOCK/8)], sizeof(uint64_t)*hash_vars);
    memcpy(hash_out, hash_values[input_len/(SHA512_MESSAGE_BLOCK/8)], hash_len);
}

void sha512_sum(unsigned char * hash_out, const unsigned char * input, uint128_t input_len) {
    sha512_sum_internal(hash_out, sizeof(uint64_t)*8, input, input_len, sha512_iv);
}
void sha384_sum(unsigned char * hash_out, const unsigned char * input, uint128_t input_len) {
    sha512_sum_internal(hash_out, sizeof(uint64_t)*7, input, input_len, sha384_iv);
}

// NOTE: FIPS 180 does include a function to generate these IVs based on _t, however since others aren't officially 
// approved and FIPS 180 also includes the IVs for these, i chose to ignore the function, see page 16(21) - 17 (22)
void sha512_224_sum(unsigned char * hash_out, const unsigned char * input, uint128_t input_len) {
    sha512_sum_internal(hash_out, SHA512_224_HASH_BYTES, input, input_len, sha512_224_iv);
}
void sha512_256_sum(unsigned char * hash_out, const unsigned char * input, uint128_t input_len) {
    sha512_sum_internal(hash_out, SHA512_256_HASH_BYTES, input, input_len, sha512_256_iv);
}