#include <assert.h>
#include <stdlib.h>
#include <gmp.h>
#include <sys/types.h>
#include "../include/crypto/secp256.h"
#include "../include/crypto/generic_weierstrass_curve.h"
#include <string.h>
// TODO: explore performance gains by passing around preallocated mpz_t structs, fixing the mpz_clear in point_and_add at the same time

#define secp256_a "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
#define secp256_b "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b" // not used in generation, only for testing whether a point is on the curve
#define secp256_prime "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
//#define secp256_order "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" // not used
#define secp256_gx "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define secp256_gy "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"


//void montgomery_mult() {
//    
//}


struct secp_key secp256_gen_public_key() {
    // TODO: use csrng, implement https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf A.2.1 - ECDSA Key Pair Generation using Extra Random Bits
    // this is just a testing setup
    unsigned char * privkey = NULL;
    privkey = malloc(SECP256_PRIVKEY_SIZE);
    assert(privkey);

    for (int i = 0; i < SECP256_PRIVKEY_SIZE/2; i++) { // doing a unsigned short cast because modulo like this isn't exactly safe
        ((unsigned short*)privkey)[i] = rand()%(1<<16);
    }

    elpoint generator, pubkey_point;
    // mpz_t order, b;
    mpz_t prime, a;

    mpz_inits(generator.x, generator.y, pubkey_point.x, pubkey_point.y, prime, a, NULL);
    //mpz_init(order);
    //mpz_init(b);

    mpz_set_str(prime, secp256_prime, 16);
    mpz_set_str(generator.x, secp256_gx, 16);
    mpz_set_str(generator.y, secp256_gy, 16);
    //mpz_set_str(order, secp256_order, 16); // never used
    //mpz_sub_ui(a, order, 3);
    mpz_set_str(a, secp256_a, 16);
    //mpz_set_str(b, secp256_b, 16); // also never used

    
    pubkey_point = double_and_add_mult(generator, privkey, prime, a, SECP256_PRIVKEY_SIZE);

    char pubkey_bytes_x[SECP256_PRIVKEY_SIZE] = {0}; // +1 to be sure
    char pubkey_bytes_y[SECP256_PRIVKEY_SIZE] = {0};

    mpz_export(pubkey_bytes_x, NULL, 1, 1, 1, 0, pubkey_point.x);
    mpz_export(pubkey_bytes_y, NULL, 1, 1, 1, 0, pubkey_point.y);

    unsigned char * pubkey = NULL;
    pubkey = malloc(SECP256_PUBKEY_SIZE);
    assert(pubkey);

    pubkey[0] = ESDSA_UNCOMPRESSED_POINT_FORMAT;
    memcpy(pubkey+1, pubkey_bytes_x, SECP256_PRIVKEY_SIZE);
    memcpy(pubkey+1+SECP256_PRIVKEY_SIZE, pubkey_bytes_y, SECP256_PRIVKEY_SIZE);

    mpz_clears(generator.x, generator.y, pubkey_point.x, pubkey_point.y, prime, a, NULL);
    //mpz_clear(order);
    //mpz_clear(b);
    return (struct secp_key) {
        .private_key = privkey,
        .public_key = pubkey
    };
}

static inline elpoint get_point_from_pubkey(const unsigned char * public_key) {
    assert(public_key[0] == ESDSA_UNCOMPRESSED_POINT_FORMAT); // the only format we support

    elpoint out;
    mpz_init(out.x);
    mpz_init(out.y);

    mpz_import(out.x, SECP256_PRIVKEY_SIZE, 1, 1, 1, 0, public_key+1);
    mpz_import(out.y, SECP256_PRIVKEY_SIZE, 1, 1, 1, 0, public_key+SECP256_PRIVKEY_SIZE+1);
    return out;
}

unsigned char * secp256_get_shared_key(const unsigned char * private_key, const unsigned char * bob_public_key) { // ECSVDP-DH for DL/ECKAS-DH1 see IEEE 1363-2000 page 29-30 and 47-48 respectively
    // note: rfc 8446 (TLS) 7.4.2 (about ECDHE) requires only the X coordinate of the shared key

    elpoint pubkey_point;
    mpz_t prime, a;

    mpz_inits(prime, a, NULL);

    mpz_set_str(prime, secp256_prime, 16);
    mpz_set_str(a, secp256_a, 16);

    pubkey_point = get_point_from_pubkey(bob_public_key);

    elpoint shared_point = double_and_add_mult(pubkey_point, private_key, prime, a, SECP256_PRIVKEY_SIZE);

    unsigned char * shared_key = NULL;
    shared_key = malloc(SECP256_PRIVKEY_SIZE);
    assert(shared_key);
    mpz_export(shared_key, NULL, 1, 1, 1, 0, shared_point.x);

    mpz_clears(pubkey_point.x, pubkey_point.y, prime, a, shared_point.x, shared_point.y, NULL);
    return shared_key;
}