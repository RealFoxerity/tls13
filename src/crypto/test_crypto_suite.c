#include <stdlib.h>
#include <stdio.h>
#include "../include/crypto/sha3.h"
#include <assert.h>
#include <string.h>

#define EXPECTED_OUT "b011a9cbb0c14f4cf7d68e50c8012168de09d1f46a9068c3ce6ecb7ca45080efb95e5425804bd430e23b59ecb2aa374c"

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_1600.pdf

int main() {
    char hash[SHA384_BYTE_SIZE] = {0};
    char input[200];
    memset(input, 0xA3, 200);

    sha3_384_hash(hash, "HelloTLS", 8);
    printf("sha3-384 hash of 'HelloTLS', expected:\nS: ");
    for (int i = 0; i < SHA384_BYTE_SIZE; i++) {
        printf("%02hhx", hash[i]);
    }
    printf("\nE: %s\n", EXPECTED_OUT);
}