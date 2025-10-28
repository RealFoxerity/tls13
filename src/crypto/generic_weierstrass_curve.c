// functions to be used by any EC functions
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include "../include/crypto/generic_weierstrass_curve.h"

static elpoint get_point(elpoint a, elpoint b, mpz_t lambda, mpz_t prime) {
    /*
        from https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
        x = lambda^2 - a.x - b.x
        y = lambda(a.x - x) - a.y
    */

    elpoint out;
    mpz_init(out.x);
    mpz_init(out.y);

    if ((mpz_cmp_ui(a.x, 0) == 0 && mpz_cmp_ui(a.y, 0) == 0) ||
        (mpz_cmp_ui(b.x, 0) == 0 && mpz_cmp_ui(b.y, 0) == 0)) return out; // identity element + anything = identity element (0 in this case)

    // TODO: check additive inverses


    mpz_t temp;
    mpz_init(temp);

    // X
    mpz_powm_ui(out.x, lambda, 2, prime); //lambda^2  mod prime
    mpz_sub(out.x, out.x, a.x);
    mpz_sub(out.x, out.x, b.x);
    mpz_mod(out.x, out.x, prime);

    // Y
    mpz_sub(temp, a.x, out.x);
    mpz_mul(out.y, lambda, temp);
    mpz_sub(out.y, out.y, a.y);
    mpz_mod(out.y, out.y, prime);

    mpz_clear(temp);
    return out;
}

elpoint point_add(elpoint a, elpoint b, mpz_t prime) {
    /*
        from https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
        lambda = (b.y - a.y)  *  inv(b.x - a.x) inverse because that can be done with modulo reduction in the same step and we avoid floating point math (no division)
    
        inv(x) = 1/x  inside a prime field (so basically a wraparound)
    */
    
    if (mpz_cmp(a.x, b.x) == 0 || mpz_cmp(a.y, b.y) == 0) {
        fprintf(stderr, "Error: Cannot add 2 identical elliptic curve points! (%s: %d)\n", __FILE__, __LINE__);
        exit(-100);
    }
    mpz_t lambda, temp;
    mpz_init(lambda);
    mpz_init(temp);


    mpz_sub(lambda, b.y, a.y); // (b.y - a.y)

    mpz_sub(temp, b.x, a.x); // (b.x - a.x)
    mpz_invert(temp, temp, prime); // inv(b.x - a.x)  mod prime
    mpz_mul(lambda, lambda, temp); // (b.y - a.y)  *  inv(b.x - a.x)

    mpz_mod(lambda, lambda, prime); // secp256 is in a prime field, the sooner we do a modulo reduction the easier multiplication is

    elpoint out = get_point(a, b, lambda, prime);

    mpz_clear(lambda);
    mpz_clear(temp);
    return out;
}

elpoint point_double(elpoint point, mpz_t a, mpz_t prime) { // A is the A from the equation
    /*
        from https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_doubling
        lambda = (3x^2  + a) * inv(2y)
    */

    mpz_t lambda, temp;
    mpz_init(lambda);
    mpz_init(temp);

    mpz_powm_ui(lambda, point.x, 2, prime); // x^2  mod prime
    mpz_mul_ui(lambda, lambda, 3); // 3x^2
    mpz_mod(lambda, lambda, prime); // since A is such a large value, it's *probably* worth to reduce the number before and after adding A
    mpz_add(lambda, lambda, a);
    mpz_mod(lambda, lambda, prime);

    mpz_mul_ui(temp, point.y, 2); // 2y
    mpz_invert(temp, temp, prime); // inv(2y)  mod prime
    mpz_mul(lambda, lambda, temp);

    mpz_mod(lambda, lambda, prime);

    elpoint out = get_point(point, point, lambda, prime);

    mpz_clear(lambda);
    mpz_clear(temp);
    return out;
}

elpoint double_and_add_mult(elpoint point, const unsigned char * scalar, mpz_t prime, mpz_t a, size_t scalar_len_bytes) {
    /*
        from https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add iterative, index decreasing
        bits = scalar
        res = out
        P = point
        note: the wikipedia article talks about the bits array as least significant to most significant bit ordered array, 
            we are doing the opposite, so the indexing is reversed from the example
    */
    elpoint out, temp;
    mpz_init(out.x);
    mpz_init(out.y);
    mpz_set(out.x, point.x);
    mpz_set(out.y, point.y);

    size_t start_bit = 0;
    for (; start_bit < scalar_len_bytes*8; start_bit++) {
        if ((scalar[start_bit/8] >> (7 - (start_bit%8))) & 1) { // the first 1 bit
            break;
        }
    }

    for (size_t i = start_bit+1; i < scalar_len_bytes*8; i++) { // +1 because we set ("added") the out point with the generator, thus using up the first bit
        temp = point_double(out, a, prime);
        mpz_clear(out.x);
        mpz_clear(out.y);
        out = temp;
        
        if ((scalar[i/8] >> (7 - (i%8))) & 1) {
            temp = point_add(out, point, prime);
            mpz_clear(out.x);
            mpz_clear(out.y);
            out = temp;
        }
    }
    return out;
}