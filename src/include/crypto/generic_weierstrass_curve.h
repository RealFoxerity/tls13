#ifndef GENERIC_WEIERSTRASS_CURVE_H
#define GENERIC_WEIERSTRASS_CURVE_H
#include <gmp.h>

struct point {
    mpz_t x, y;
} typedef elpoint;

//elpoint point_add(elpoint a, elpoint b, mpz_t prime); // doesn't need to be externally available
//elpoint point_double(elpoint point, mpz_t a, mpz_t prime);
elpoint double_and_add_mult(elpoint point, const unsigned char * scalar, mpz_t prime, mpz_t a, size_t scalar_len_bytes);
#endif