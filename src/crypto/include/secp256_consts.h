#ifndef SECP256_CONSTS
#define SECP256_CONSTS
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
#define secp256_a "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
#define secp256_b "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b" // not used in generation, only for testing whether a point is on the curve
#define secp256_prime "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define secp256_order "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" // order of the point G, not the curve, used in ECDSA
#define secp256_order_len ((sizeof(secp256_order)-1)/2)
#define secp256_gx "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define secp256_gy "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

#endif