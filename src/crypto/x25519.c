#include "../include/crypto/x25519.h"
#include <stdlib.h>
#include <assert.h>


// math shamelessly stolen from https://martin.kleppmann.com/papers/curve25519.pdf
typedef unsigned char u8;
typedef long long i64;
typedef i64 field_elem[16];

static void unpack25519(field_elem out, const u8 *in) {
    int i;
    for (i = 0; i < 16; ++i) out[i] = in[2*i] + ((i64) in[2*i + 1] << 8);
    out[15] &= 0x7fff;
}

static void carry25519(field_elem elem) {
    int i;
    i64 carry;
    for (i = 0; i < 16; ++i) {
        carry = elem[i] >> 16;
        elem[i] -= carry << 16;
        if (i < 15) elem[i + 1] += carry; else elem[0] += 38 * carry;
    }
}
static void fadd(field_elem out, const field_elem a, const field_elem b) /* out = a + b */
{
int i;
for (i = 0; i < 16; ++i) out[i] = a[i] + b[i];
}
static void fsub(field_elem out, const field_elem a, const field_elem b) /* out = a - b */
{
int i;
for (i = 0; i < 16; ++i) out[i] = a[i] - b[i];
}
static void fmul(field_elem out, const field_elem a, const field_elem b) /* out = a * b */
{
i64 i, j, product[31];
for (i = 0; i < 31; ++i) product[i] = 0;
for (i = 0; i < 16; ++i) {
for (j = 0; j < 16; ++j) product[i+j] += a[i] * b[j];
}
for (i = 0; i < 15; ++i) product[i] += 38 * product[i + 16];
for (i = 0; i < 16; ++i) out[i] = product[i];
carry25519(out);
carry25519(out);
}

Keys x25519_gen_keypair() {
    Keys out = {0};
    out.private_key.len = out.public_key.len = X25519_KEY_SIZE;
    
    out.private_key.data = malloc(X25519_KEY_SIZE);
    assert(out.private_key.data != NULL);

    out.public_key.data = malloc(X25519_KEY_SIZE);
    assert(out.public_key.data != NULL);

    for (int i = 0; i<X25519_KEY_SIZE/sizeof(int); i++) {
        ((int*)out.private_key.data)[i] = random();
    }

    // calculation of the point
    // y^2 = x^3 + 486662x^2 + x
    // x = 9
    
}