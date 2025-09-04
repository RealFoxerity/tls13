#include <stdlib.h>
#include <stdio.h>
#include "../include/crypto/sha3.h"
#include "../include/crypto/sha2.h"
#include "../include/crypto/aes.h"
#include <assert.h>
#include <string.h>


const unsigned char * sha3_expected[] = {
    (unsigned char *)"91028287c6f69e381f349a22cade0761b853b03e05b3d5a7d8ccfb90",
    (unsigned char *)"72ae713cdd9c0620112c6d70a86db9fa476d4abe15302791e59696b5f9b74086",
    (unsigned char *)"b011a9cbb0c14f4cf7d68e50c8012168de09d1f46a9068c3ce6ecb7ca45080efb95e5425804bd430e23b59ecb2aa374c",
    (unsigned char *)"41b871021f2f785d0bd5b2668384a8c646fa56b32da4cffc63c7122c0110190875f15a4ebb303a5bae989ca26526320babc7a5deca7ae46b9a8e3f9745ab8bda"
};

const unsigned char * sha2_expected[] = {
    (unsigned char *)"3e3fc7565541cf6c5910a13627c261b47082b1e3",
    (unsigned char *)"2106b9645a05469ecaae5d7d67eed1a482ac5668db3cb601b23846b0",
    (unsigned char *)"2db449ec6c0e4783ba06a664fe2a6941c8ac4296af0776ff8e668c0c577c786c",
    (unsigned char *)"2bf42ae199fd97a8d4fa7b09130763dc25a866426a9db0602805e080838116bf429baf77f5c49bc9ea813cb8bcfd61ac",
    (unsigned char *)"4395f6c38267d1d00f62d7ede65bcc63afffe39dc49379166e36559e95f1bffca0d595595f81e498d6ccf320cda3b9ee07d4294012e54760e69c0786795c9be6",
    (unsigned char *)"9630c93173c238023c85fd3ab5d6604340cf81faade0d990ea99961b",
    (unsigned char *)"a82295b6712fcc648d04a8f918f6e003c12e4ba4ac1c4e0d9c02848fe29b52da"
};

const unsigned char * aes_data[] = {
    (unsigned char *)"\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34"
};
const unsigned char * aes_keys[] = {
    (unsigned char *)"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
};
const unsigned char * aes_ciphertext[] = {
    (unsigned char*)"\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32"
};

#define max(a,b) ((a)>(b)?(a):(b))

int main() {
    unsigned char hash[max(SHA3_512_HASH_BYTES, SHA512_HASH_BYTES)];

    memset(hash, 0, SHA3_224_HASH_BYTES);
    sha3_224_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha3-224 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA3_224_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha3_expected[0]);

    memset(hash, 0, SHA3_256_HASH_BYTES);
    sha3_256_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha3-256 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA3_256_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha3_expected[1]);

    memset(hash, 0, SHA3_384_HASH_BYTES);
    sha3_384_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha3-384 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA3_384_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha3_expected[2]);

    memset(hash, 0, SHA3_512_HASH_BYTES);
    sha3_512_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha3-512 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA3_512_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha3_expected[3]);

    printf("\n\n");

    memset(hash, 0, SHA1_HASH_BYTES);
    sha1_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha1 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA1_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[0]);

    memset(hash, 0, SHA224_HASH_BYTES);
    sha224_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha224 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA224_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[1]);

    memset(hash, 0, SHA256_HASH_BYTES);
    sha256_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha256 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA256_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[2]);

    memset(hash, 0, SHA384_HASH_BYTES);
    sha384_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha384 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA384_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[3]);

    memset(hash, 0, SHA512_HASH_BYTES);
    sha512_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha512 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA512_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[4]);

    memset(hash, 0, SHA512_224_HASH_BYTES);
    sha512_224_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha512/224 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA512_224_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[5]);

    memset(hash, 0, SHA512_256_HASH_BYTES);
    sha512_256_sum(hash, (unsigned char *)"HelloTLS", 8);
    printf("sha512/256 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA512_256_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[6]);

    printf("\n\n");

    memset(hash, 0, AES_BLOCK_SIZE);

    printf("Testing raw AES-128 encryption\n");
    aes_128_enc(aes_data[0], hash, aes_keys[0]);
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02hhx ", hash[i]);
        if (hash[i] != aes_ciphertext[0][i]) {
            printf("--\nAES-128 encrypt failed!");
            break;
        }
    }
    printf("\n");

    memset(hash, 0, AES_BLOCK_SIZE);

    printf("Testing raw AES-128 decryption\n");
    aes_128_dec(aes_ciphertext[0], hash, aes_keys[0]);
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02hhx ", hash[i]);
        if (hash[i] != aes_data[0][i]) {
            printf("--\nAES-128 decrypt failed!");
            break;
        }
    }
    printf("\n");
    return 0;
}