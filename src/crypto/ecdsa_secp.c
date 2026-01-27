// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf 6.4 - ECDSA Digital Signature Generation and Verification
#include "include/secp256.h"
#include "include/secp256_consts.h"
#include "include/generic_weierstrass_curve.h"
#include "include/ecdsa_secp256.h"
#include "include/hmac.h"
#include "include/sha2.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

char ecdsa_verify_secp256r1(
        struct ECDSA_signature signature, enum hmac_supported_hashes hash_type, 
        const unsigned char * data, size_t data_len,
        struct secp_key public_key);

struct ECDSA_signature ecdsa_sign_secp256r1(
        enum hmac_supported_hashes hash_type, 
        const unsigned char * data, size_t data_len,  
        struct secp_key private_key) {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf 6.4.1
    assert(data);
    assert(private_key.private_key);
    
    struct ECDSA_signature out = {NULL};

    size_t hash_size = 0;
    unsigned char * hash = NULL;
    switch (hash_type) {
        case HMAC_SHA1:
            hash_size = SHA1_HASH_BYTES;
            break;
        case HMAC_SHA2_224:
            hash_size = SHA224_HASH_BYTES;
            break;
        case HMAC_SHA2_256:
            hash_size = SHA256_HASH_BYTES;
            break;
        case HMAC_SHA2_384:
            hash_size = SHA384_HASH_BYTES;
            break;
        case HMAC_SHA2_512:
            hash_size = SHA512_HASH_BYTES;
            break;
        default:
            fprintf(stderr, "Unknown hash type specified for ECDSA operation\n");
            return out;
    }

    hash = malloc(hash_size);
    assert(hash);

    switch (hash_type) {
        case HMAC_SHA1:
            sha1_sum(hash, data, data_len);
            break;
        case HMAC_SHA2_224:
            sha224_sum(hash, data, data_len);
            break;
        case HMAC_SHA2_256:
            sha256_sum(hash, data, data_len);
            break;
        case HMAC_SHA2_384:
            sha384_sum(hash, data, data_len);
            break;
        case HMAC_SHA2_512:
            sha512_sum(hash, data, data_len);
            break;
    }

    mpz_t hash_integer, per_message_secret, s, secp256_generator_order, a;
    elpoint R, secp256_generator;

    mpz_t private_key_int;
    mpz_init(private_key_int);
    mpz_import(private_key_int, SECP256_PRIVKEY_SIZE, 1, 1, 1, 0, private_key.private_key);

    unsigned char pms_bytes[secp256_order_len] = {0};
    mpz_inits(hash_integer, per_message_secret, s, secp256_generator_order, a, R.x, R.y, secp256_generator.x, secp256_generator.y, NULL);

    mpz_set_str(secp256_generator_order, secp256_order, 16);
    mpz_set_str(secp256_generator.x, secp256_gx, 16);
    mpz_set_str(secp256_generator.y, secp256_gy, 16);
    mpz_set_str(a, secp256_a, 16);

    mpz_import(hash_integer, hash_size < secp256_order_len ? hash_size : secp256_order_len, 1, 1, 1, 0, hash); 
    // note: standard calls for bits, just so happens that they are divisible by 8, so we can use bytes

    free(hash);

    gmp_randstate_t gmp_rs;
    gmp_randinit_mt(gmp_rs); // TODO: csprng?
    retry:
    mpz_urandomm(per_message_secret, gmp_rs, secp256_generator_order);

    mpz_export(pms_bytes, NULL, 1, 1, 1, 0, per_message_secret);
    mpz_invert(per_message_secret, per_message_secret, secp256_generator_order);

    R = double_and_add_mult(secp256_generator, pms_bytes, secp256_generator_order, a, sizeof(pms_bytes));
    // note: we can skip steps 6 since affine representation in my implementation is already used
    // note 2: we don't need another r variable since we don't need the point anymore
    mpz_mod(R.x, R.x, secp256_generator_order);

    if (mpz_cmp_ui(R.x, 0) == 0) goto retry;

    mpz_set(s, R.x);
    mpz_mul(s, s, private_key_int);
    mpz_add(s, s, hash_integer);
    mpz_mul(s, s, per_message_secret);
    mpz_mod(s, s, secp256_generator_order);

    if (mpz_cmp_ui(s, 0) == 0) goto retry;


    unsigned char * r_bytes = calloc(ECDSA_SECP256_SIG_SIZE,1);
    unsigned char * s_bytes = calloc(ECDSA_SECP256_SIG_SIZE,1);
    assert(r_bytes);
    assert(s_bytes);

    mpz_export(r_bytes, NULL, 1, 1, 1, 0, R.x);
    mpz_export(s_bytes, NULL, 1, 1, 1, 0, s);

    out.r = r_bytes;
    out.s = s_bytes;

    mpz_clears(hash_integer, per_message_secret, s, secp256_generator_order, a, R.x, R.y, secp256_generator.x, secp256_generator.y, NULL);
    mpz_clear(private_key_int);
    gmp_randclear(gmp_rs);

    return out;
}
