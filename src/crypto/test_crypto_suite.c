#include <stdint.h>
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

    uint8_t gcm_test_aead_tag[GCM_BLOCK_SIZE] = {0};
    uint8_t * ciphertext_gcm;
    /*
    printf("Testing AES-128-GCM AEAD Authenticated Encryption - test case 1\n");
    uint8_t gcm_test_1_k[AES_128_KEY_LEN] = {0};
    const uint8_t gcm_test_1_aead_expected[] = "\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a";
    uint8_t gcm_test_1_iv[12] = {0};
    ciphertext_gcm = aes_128_gcm_enc(NULL, 0, NULL, 0, gcm_test_1_iv, 12, gcm_test_aead_tag, gcm_test_1_k);
    for (int i = 0; i < sizeof(gcm_test_1_aead_expected) -1; i++) { //null byte
        if (gcm_test_aead_tag[i] != gcm_test_1_aead_expected[i]) {
            printf("Test 1 authenticated encrypt failed on byte %d - AEAD tag incorrect!\n", i);
            exit(1);
        }
    }
    free(ciphertext_gcm);
    printf("AES-128-GCM AEAD Authenticated Encryption - test case 1 - passed\n");
   
    printf("Testing AES-128-GCM AEAD Authenticated Encryption - test case 2\n");
    uint8_t gcm_test_2_k[AES_128_KEY_LEN] = {0};
    uint8_t gcm_test_2_p[AES_BLOCK_SIZE] = {0};
    const uint8_t gcm_test_2_aead_expected[] = "\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf";
    const uint8_t gcm_test_2_ciphertext_expected[] = "\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78";
    memset(gcm_test_aead_tag, 0, GCM_BLOCK_SIZE);
    uint8_t gcm_test_2_iv[12] = {0};
    ciphertext_gcm = aes_128_gcm_enc(gcm_test_2_p, AES_BLOCK_SIZE, NULL, 0, gcm_test_2_iv, 12, gcm_test_aead_tag, gcm_test_2_k);
    for (int i = 0; i < sizeof(gcm_test_2_aead_expected) - 1; i++) {
        if (gcm_test_aead_tag[i] != gcm_test_2_aead_expected[i]) {
            printf("Test 2 authenticated encrypt failed on byte %d - AEAD tag incorrect!\n", i);
            exit(1);
        }
    }
    for (int i = 0; i < sizeof(gcm_test_2_ciphertext_expected) - 1; i++) {
        if (ciphertext_gcm[i] != gcm_test_2_ciphertext_expected[i]) {
            printf("Test 2 authenticated encrypt failed on byte %d - Ciphertext incorrect!\n", i);
            exit(1);
        }
    }
    free(ciphertext_gcm);
    printf("AES-128-GCM AEAD Authenticated Encryption - test case 2 - passed\n");
    */
    printf("Testing AES-128-GCM AEAD Authenticated Encryption - test case 3\n");
    uint8_t gcm_test_3_k[AES_128_KEY_LEN] = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08";
    uint8_t gcm_test_3_p[] = 
"\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\
\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\
\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\
\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55";
    const uint8_t gcm_test_3_aead_expected[] = "\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf";
    const uint8_t gcm_test_3_ciphertext_expected[] = "\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78";
    memset(gcm_test_aead_tag, 0, GCM_BLOCK_SIZE);
    uint8_t gcm_test_3_iv[] = "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88";
    ciphertext_gcm = aes_128_gcm_enc(
        gcm_test_3_p, sizeof(gcm_test_3_p)-1, 
        NULL, 0, 
        gcm_test_3_iv, sizeof(gcm_test_3_iv)-1,
        gcm_test_aead_tag, gcm_test_3_k);

    for (int i = 0; i < sizeof(gcm_test_3_aead_expected) - 1; i++) {
        if (gcm_test_aead_tag[i] != gcm_test_3_aead_expected[i]) {
            printf("Test 3 authenticated encrypt failed on byte %d - AEAD tag incorrect!\n", i);
            break;
            //exit(1);
        }
    }
    for (int i = 0; i < sizeof(gcm_test_3_ciphertext_expected) - 1; i++) {
        if (ciphertext_gcm[i] != gcm_test_3_ciphertext_expected[i]) {
            printf("Test 3 authenticated encrypt failed on byte %d - Ciphertext incorrect!\n", i);
            exit(1);
        }
    }
    free(ciphertext_gcm);
    printf("AES-128-GCM AEAD Authenticated Encryption - test case 3 - passed\n");

    return 0;
}