#include <stdlib.h>
#include <stdio.h>
#include "../include/crypto/sha3.h"
#include <assert.h>
#include <string.h>

#define EXPECTED_OUT "E76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA81B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00"

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_1600.pdf

int main() {
    char hash[SHA384_BYTE_SIZE] = {0};
    char input[200];
    memset(input, 0xA3, 200);

    sha3_384_hash(hash, input, 200);
    printf("sha384 hash of 'HelloTLS': ");
    for (int i = 0; i < SHA384_BYTE_SIZE; i++) {
        printf("%02hhx", hash[i]);
    }
    printf("\nExpected out: %s\n", EXPECTED_OUT);
}