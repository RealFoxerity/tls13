#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "include/sha3.h"
#include "include/sha2.h"
#include "include/aes.h"
#include "include/hmac.h"
#include "include/hkdf.h"
#include "include/secp256.h"
#include "include/ecdsa_secp256.h"
#include <assert.h>
#include <string.h>
#include <unistd.h>


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
    (unsigned char *)"a82295b6712fcc648d04a8f918f6e003c12e4ba4ac1c4e0d9c02848fe29b52da",
    (unsigned char *)"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // sha256 of nothing
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

const unsigned char plain_hkdf_ikm[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
const unsigned char plain_hkdf_salt[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
const unsigned char plain_hkdf_info[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9";
const size_t plain_hkdf_okm_size = 42;

const unsigned char tls13_xargs_org_test_client_hello[] = "\x01\x00\x00\xf4\x03\x03\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x08\x13\x02\x13\x03\x13\x01\x00\xff\x01\x00\x00\xa3\x00\x00\x00\x18\x00\x16\x00\x00\x13\x65\x78\x61\x6d\x70\x6c\x65\x2e\x75\x6c\x66\x68\x65\x69\x6d\x2e\x6e\x65\x74\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x16\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x23\x00\x00\x00\x16\x00\x00\x00\x17\x00\x00\x00\x0d\x00\x1e\x00\x1c\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x00\x2b\x00\x03\x02\x03\x04\x00\x2d\x00\x02\x01\x01\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x35\x80\x72\xd6\x36\x58\x80\xd1\xae\xea\x32\x9a\xdf\x91\x21\x38\x38\x51\xed\x21\xa2\x8e\x3b\x75\xe9\x65\xd0\xd2\xcd\x16\x62\x54";
const unsigned char tls13_xargs_org_test_server_hello[] = "\x02\x00\x00\x76\x03\x03\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x20\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x13\x02\x00\x00\x2e\x00\x2b\x00\x02\x03\x04\x00\x33\x00\x24\x00\x1d\x00\x20\x9f\xd7\xad\x6d\xcf\xf4\x29\x8d\xd3\xf9\x6d\x5b\x1b\x2a\xf9\x10\xa0\x53\x5b\x14\x88\xd7\xf8\xfa\xbb\x34\x9a\x98\x28\x80\xb6\x15";

const char tls13_xargs_org_test_transcript_hash[] = "e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd";

#define max(a,b) ((a)>(b)?(a):(b))

int main() {
    unsigned char hash[max(SHA3_512_HASH_BYTES, SHA512_HASH_BYTES)];
    sha2_ctx_t context;

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
    sha224_init(&context);
    sha224_update(&context, (unsigned char*)"HelloTLS", 8);
    sha224_finalize(&context, hash);
    printf("sha224 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA224_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[1]);

    memset(hash, 0, SHA256_HASH_BYTES);

    sha256_init(&context);
    sha256_update(&context, (unsigned char*)"HelloTLS", 8);
    sha256_finalize(&context, hash);
    printf("sha256 hash of 'HelloTLS', expected:\nS: ");
    for (int j = 0; j < SHA256_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[2]);

    memset(hash, 0, SHA256_HASH_BYTES);
    sha256_sum(hash, NULL, 0);
    printf("sha256 hash of empty string, expected:\nS: ");
    for (int j = 0; j < SHA256_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", sha2_expected[7]);

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
    uint8_t * ciphertext_gcm, * plaintext_gcm;
    
    printf("Testing AES-128-GCM AEAD Authenticated Encryption - test case 1 (AEAD tag generation)\n");
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
    printf("AES-128-GCM AEAD Authenticated Encryption - test case 1 - passed\n");

    printf("Testing AES-128-GCM AEAD Authenticated Decryption - test case 1 (AEAD tag generation)\n");
    plaintext_gcm = aes_128_gcm_dec(NULL, 0, NULL, 0, gcm_test_1_iv, 12, gcm_test_aead_tag, gcm_test_1_k);
    if (plaintext_gcm == (uint8_t*)-1) {
        printf("Test 1 authenticated decrypt failed - AEAD tag mismatch\n");
        exit(1);
    }

    free(ciphertext_gcm); // won't do anything because this will be NULL, but to be safe
    free(plaintext_gcm);
    printf("AES-128-GCM AEAD Authenticated Decryption - test case 1 - passed\n");
    /*
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
    
    printf("Testing AES-128-GCM AEAD Authenticated Encryption - test case 3\n");
    uint8_t gcm_test_3_k[AES_128_KEY_LEN] = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08";
    uint8_t gcm_test_3_p[] = 
"\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\
\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\
\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\
\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55";
    const uint8_t gcm_test_3_aead_expected[] = "\x4d\x5c\x2a\xf3\x27\xcd\x64\xa6\x2c\xf3\x5a\xbd\x2b\xa6\xfa\xb4";
    const uint8_t gcm_test_3_ciphertext_expected[] = 
"\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c\
\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e\
\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05\
\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91\x47\x3f\x59\x85";
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
            exit(1);
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
    */

    printf("Testing AES-128-GCM AEAD Authenticated Encryption - test case 6\n");
    uint8_t gcm_test_6_k[AES_128_KEY_LEN] = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08";
    uint8_t gcm_test_6_p[] = 
"\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\
\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\
\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\
\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39";
    const uint8_t gcm_test_6_aad[] = "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2";
    const uint8_t gcm_test_6_aead_expected[] = "\x61\x9c\xc5\xae\xff\xfe\x0b\xfa\x46\x2a\xf4\x3c\x16\x99\xd0\x50";
    const uint8_t gcm_test_6_ciphertext_expected[] = 
"\x8c\xe2\x49\x98\x62\x56\x15\xb6\x03\xa0\x33\xac\xa1\x3f\xb8\x94\
\xbe\x91\x12\xa5\xc3\xa2\x11\xa8\xba\x26\x2a\x3c\xca\x7e\x2c\xa7\
\x01\xe4\xa9\xa4\xfb\xa4\x3c\x90\xcc\xdc\xb2\x81\xd4\x8c\x7c\x6f\
\xd6\x28\x75\xd2\xac\xa4\x17\x03\x4c\x34\xae\xe5";
    memset(gcm_test_aead_tag, 0, GCM_BLOCK_SIZE);
    uint8_t gcm_test_6_iv[] = 
"\x93\x13\x22\x5d\xf8\x84\x06\xe5\x55\x90\x9c\x5a\xff\x52\x69\xaa\
\x6a\x7a\x95\x38\x53\x4f\x7d\xa1\xe4\xc3\x03\xd2\xa3\x18\xa7\x28\
\xc3\xc0\xc9\x51\x56\x80\x95\x39\xfc\xf0\xe2\x42\x9a\x6b\x52\x54\
\x16\xae\xdb\xf5\xa0\xde\x6a\x57\xa6\x37\xb3\x9b";
    ciphertext_gcm = aes_128_gcm_enc(
        gcm_test_6_p, sizeof(gcm_test_6_p)-1, 
        gcm_test_6_aad, sizeof(gcm_test_6_aad)-1, 
        gcm_test_6_iv, sizeof(gcm_test_6_iv)-1,
        gcm_test_aead_tag, gcm_test_6_k);

    for (int i = 0; i < sizeof(gcm_test_6_aead_expected) - 1; i++) {
        if (gcm_test_aead_tag[i] != gcm_test_6_aead_expected[i]) {
            printf("Test 6 authenticated encrypt failed on byte %d - AEAD tag incorrect!\n", i);
            exit(1);
        }
    }
    for (int i = 0; i < sizeof(gcm_test_6_ciphertext_expected) - 1; i++) {
        if (ciphertext_gcm[i] != gcm_test_6_ciphertext_expected[i]) {
            printf("Test 6 authenticated encrypt failed on byte %d - Ciphertext incorrect!\n", i);
            exit(1);
        }
    }
    printf("AES-128-GCM AEAD Authenticated Encryption - test case 6 - passed\n");
    printf("Testing AES-128-GCM AEAD Authenticated Decryption - test case 6\n");

    plaintext_gcm = aes_128_gcm_dec(
        ciphertext_gcm, sizeof(gcm_test_6_p)-1, 
        gcm_test_6_aad, sizeof(gcm_test_6_aad)-1,
        gcm_test_6_iv, sizeof(gcm_test_6_iv)-1,
        gcm_test_aead_tag, gcm_test_6_k);
    if (plaintext_gcm == (uint8_t*)-1) {
        printf("Test 6 authenticated decrypt failed - auth tag mismatch\n");
        exit(1);
    }
    for (int i = 0; i < sizeof(gcm_test_6_p)-1; i++) {
        if (plaintext_gcm[i] != gcm_test_6_p[i]) {
            printf("Test 6 authenticated decrypt failed on byte %d - Plaintext incorrect!\n", i);
            exit(1);
        }
    }
    free(ciphertext_gcm);
    free(plaintext_gcm);
    printf("AES-128-GCM AEAD Authenticated Decryption - test case 6 - passed\n");

    printf("Testing AES-192-GCM AEAD Authenticated Encryption - test case 12\n");
    uint8_t gcm_test_12_k[AES_192_KEY_LEN] = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c";
    uint8_t gcm_test_12_p[] = 
"\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\
\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\
\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\
\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39";
    const uint8_t gcm_test_12_aad[] = "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2";
    const uint8_t gcm_test_12_aead_expected[] = "\xdc\xf5\x66\xff\x29\x1c\x25\xbb\xb8\x56\x8f\xc3\xd3\x76\xa6\xd9";
    const uint8_t gcm_test_12_ciphertext_expected[] = 
"\xd2\x7e\x88\x68\x1c\xe3\x24\x3c\x48\x30\x16\x5a\x8f\xdc\xf9\xff\
\x1d\xe9\xa1\xd8\xe6\xb4\x47\xef\x6e\xf7\xb7\x98\x28\x66\x6e\x45\
\x81\xe7\x90\x12\xaf\x34\xdd\xd9\xe2\xf0\x37\x58\x9b\x29\x2d\xb3\
\xe6\x7c\x03\x67\x45\xfa\x22\xe7\xe9\xb7\x37\x3b";
    memset(gcm_test_aead_tag, 0, GCM_BLOCK_SIZE);
    uint8_t gcm_test_12_iv[] = 
"\x93\x13\x22\x5d\xf8\x84\x06\xe5\x55\x90\x9c\x5a\xff\x52\x69\xaa\
\x6a\x7a\x95\x38\x53\x4f\x7d\xa1\xe4\xc3\x03\xd2\xa3\x18\xa7\x28\
\xc3\xc0\xc9\x51\x56\x80\x95\x39\xfc\xf0\xe2\x42\x9a\x6b\x52\x54\
\x16\xae\xdb\xf5\xa0\xde\x6a\x57\xa6\x37\xb3\x9b";
    ciphertext_gcm = aes_192_gcm_enc(
        gcm_test_12_p, sizeof(gcm_test_12_p)-1, 
        gcm_test_12_aad, sizeof(gcm_test_12_aad)-1, 
        gcm_test_12_iv, sizeof(gcm_test_12_iv)-1,
        gcm_test_aead_tag, gcm_test_12_k);

    for (int i = 0; i < sizeof(gcm_test_12_aead_expected) - 1; i++) {
        if (gcm_test_aead_tag[i] != gcm_test_12_aead_expected[i]) {
            printf("Test 12 authenticated encrypt failed on byte %d - AEAD tag incorrect!\n", i);
            exit(1);
        }
    }
    for (int i = 0; i < sizeof(gcm_test_12_ciphertext_expected) - 1; i++) {
        if (ciphertext_gcm[i] != gcm_test_12_ciphertext_expected[i]) {
            printf("Test 12 authenticated encrypt failed on byte %d - Ciphertext incorrect!\n", i);
            exit(1);
        }
    }
    printf("AES-192-GCM AEAD Authenticated Encryption - test case 12 - passed\n");
    printf("Testing AES-192-GCM AEAD Authenticated Decryption - test case 12\n");

    plaintext_gcm = aes_192_gcm_dec(
        ciphertext_gcm, sizeof(gcm_test_12_p)-1, 
        gcm_test_12_aad, sizeof(gcm_test_12_aad)-1,
        gcm_test_12_iv, sizeof(gcm_test_12_iv)-1,
        gcm_test_aead_tag, gcm_test_12_k);
    if (plaintext_gcm == (uint8_t*)-1) {
        printf("Test 12 authenticated decrypt failed - auth tag mismatch\n");
        exit(1);   
    }
    for (int i = 0; i < sizeof(gcm_test_12_p)-1; i++) {
        if (plaintext_gcm[i] != gcm_test_12_p[i]) {
            printf("Test 12 authenticated decrypt failed on byte %d - Plaintext incorrect!\n", i);
            exit(1);
        }
    }
    free(ciphertext_gcm);
    free(plaintext_gcm);
    printf("AES-192-GCM AEAD Authenticated Decryption - test case 12 - passed\n");


    printf("Testing AES-256-GCM AEAD Authenticated Encryption - test case 18\n");
    uint8_t gcm_test_18_k[AES_256_KEY_LEN] = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08";
    uint8_t gcm_test_18_p[] = 
"\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\
\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\
\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\
\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39";
    const uint8_t gcm_test_18_aad[] = "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2";
    const uint8_t gcm_test_18_aead_expected[] = "\xa4\x4a\x82\x66\xee\x1c\x8e\xb0\xc8\xb5\xd4\xcf\x5a\xe9\xf1\x9a";
    const uint8_t gcm_test_18_ciphertext_expected[] = 
"\x5a\x8d\xef\x2f\x0c\x9e\x53\xf1\xf7\x5d\x78\x53\x65\x9e\x2a\x20\
\xee\xb2\xb2\x2a\xaf\xde\x64\x19\xa0\x58\xab\x4f\x6f\x74\x6b\xf4\
\x0f\xc0\xc3\xb7\x80\xf2\x44\x45\x2d\xa3\xeb\xf1\xc5\xd8\x2c\xde\
\xa2\x41\x89\x97\x20\x0e\xf8\x2e\x44\xae\x7e\x3f";
    memset(gcm_test_aead_tag, 0, GCM_BLOCK_SIZE);
    uint8_t gcm_test_18_iv[] = 
"\x93\x13\x22\x5d\xf8\x84\x06\xe5\x55\x90\x9c\x5a\xff\x52\x69\xaa\
\x6a\x7a\x95\x38\x53\x4f\x7d\xa1\xe4\xc3\x03\xd2\xa3\x18\xa7\x28\
\xc3\xc0\xc9\x51\x56\x80\x95\x39\xfc\xf0\xe2\x42\x9a\x6b\x52\x54\
\x16\xae\xdb\xf5\xa0\xde\x6a\x57\xa6\x37\xb3\x9b";
    ciphertext_gcm = aes_256_gcm_enc(
        gcm_test_18_p, sizeof(gcm_test_18_p)-1, 
        gcm_test_18_aad, sizeof(gcm_test_18_aad)-1, 
        gcm_test_18_iv, sizeof(gcm_test_18_iv)-1,
        gcm_test_aead_tag, gcm_test_18_k);

    for (int i = 0; i < sizeof(gcm_test_18_aead_expected) - 1; i++) {
        if (gcm_test_aead_tag[i] != gcm_test_18_aead_expected[i]) {
            printf("Test 18 authenticated encrypt failed on byte %d - AEAD tag incorrect!\n", i);
            exit(1);
        }
    }
    for (int i = 0; i < sizeof(gcm_test_18_ciphertext_expected) - 1; i++) {
        if (ciphertext_gcm[i] != gcm_test_18_ciphertext_expected[i]) {
            printf("Test 18 authenticated encrypt failed on byte %d - Ciphertext incorrect!\n", i);
            exit(1);
        }
    }
    printf("AES-256-GCM AEAD Authenticated Encryption - test case 18 - passed\n");
    printf("Testing AES-256-GCM AEAD Authenticated Decryption - test case 18\n");

    plaintext_gcm = aes_256_gcm_dec(
        ciphertext_gcm, sizeof(gcm_test_18_p)-1, 
        gcm_test_18_aad, sizeof(gcm_test_18_aad)-1,
        gcm_test_18_iv, sizeof(gcm_test_18_iv)-1,
        gcm_test_aead_tag, gcm_test_18_k);
    if (plaintext_gcm == (uint8_t*)-1) {
        printf("Test 6 authenticated decrypt failed - auth tag mismatch\n");
        exit(1);   
    }
    for (int i = 0; i < sizeof(gcm_test_18_p)-1; i++) {
        if (plaintext_gcm[i] != gcm_test_18_p[i]) {
            printf("Test 18 authenticated decrypt failed on byte %d - Plaintext incorrect!\n", i);
            exit(1);
        }
    }
    free(ciphertext_gcm);
    free(plaintext_gcm);
    printf("AES-256-GCM AEAD Authenticated Decryption - test case 18 - passed\n");
    printf("\n\n");

    printf("HMAC SHA-256 test, string \"Hello\", key \"TLS\", no null bytes, expected:\nHMAC: ");
    unsigned char * code = hmac(HMAC_SHA2_256, (unsigned char *)"TLS", 3, (unsigned char *)"Hello", 5);
    for (int i = 0; i < SHA256_HASH_BYTES; i++) {
        printf("%02hhx", code[i]);
    }
    free(code);
    printf("\nE:    1090f043a91a1b50054e75d54fcb5e1a5309cb77a0bafa2669cbf9c75fa810fe\n");

    printf("HMAC SHA-384 test, string \"Hello\", key \"TLS\", no null bytes, expected:\nHMAC: ");
    code = hmac(HMAC_SHA2_384, (unsigned char *)"TLS", 3, (unsigned char *)"Hello", 5);
    for (int i = 0; i < SHA384_HASH_BYTES; i++) {
        printf("%02hhx", code[i]);
    }
    free(code);
    printf("\nE:    d7f8a170daa814b626900f480844901f6026393ecc5302e0af42c75818cd935434a6142143c6b2231eff319d44fb3352\n");

    printf("HMAC SHA-384 test, null block, null key - TLS early secret no PSK, expected:\nHMAC: ");
    code = hmac(HMAC_SHA2_384, NULL, 0, (unsigned char *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", SHA384_HASH_BYTES);
    for (int i = 0; i < SHA384_HASH_BYTES; i++) {
        printf("%02hhx", code[i]);
    }
    free(code);
    printf("\nE:    7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5\n");

    printf("Plain HKDF SHA-256 test, rfc 5869 test case 1\n\tPRK: ");
    struct prk plain_hkdf_prk = hkdf_extract(HMAC_SHA2_256, plain_hkdf_salt, sizeof(plain_hkdf_salt)-1, plain_hkdf_ikm, sizeof(plain_hkdf_ikm) - 1);
    for (int i = 0; i < plain_hkdf_prk.prk_len; i++) {
        printf("%02hhx", plain_hkdf_prk.prk[i]);
    }
    printf("\n\tE:   077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5\n\tOKM: ");
    unsigned char * plain_hkdf_okm = hkdf_expand(HMAC_SHA2_256, plain_hkdf_prk, plain_hkdf_info, sizeof(plain_hkdf_info)-1, plain_hkdf_okm_size);
    for (int i = 0; i < plain_hkdf_okm_size; i++) {
        printf("%02hhx", plain_hkdf_okm[i]);
    }
    printf("\n\tE:   3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865\n");
    free(plain_hkdf_okm);
    hkdf_free(plain_hkdf_prk);

    printf("SHA-384 transcript hash test from tls13.xargs.org, expected:\nS: ");
    sha2_ctx_t thash_ctx;
    sha384_init(&thash_ctx);
    sha384_update(&thash_ctx, tls13_xargs_org_test_client_hello, sizeof(tls13_xargs_org_test_client_hello)-1);
    sha384_update(&thash_ctx, tls13_xargs_org_test_server_hello, sizeof(tls13_xargs_org_test_server_hello)-1);
    sha384_finalize(&thash_ctx, hash);
    for (int j = 0; j < SHA384_HASH_BYTES; j++) {
        printf("%02hhx", hash[j]);
    }
    printf("\nE: %s\n", tls13_xargs_org_test_transcript_hash);


    printf("secp256r1 random keys test, use openssl and/or e.g. https://rtos.dev/tools/ecc to verify\n");

    struct secp_key A, B;
    A = secp256_gen_public_key();
    B = secp256_gen_public_key();

    unsigned char * shared_secret = secp256_get_shared_key(A.private_key, B.public_key);

    printf("alice private key: ");
    for (int i = 0; i < SECP256_PRIVKEY_SIZE; i++) printf("%02hhx", A.private_key[i]);
    printf("\nalice public key: ");
    for (int i = 0; i < SECP256_PUBKEY_SIZE; i++) printf("%02hhx", A.public_key[i]);

    printf("\nbob private key: ");
    for (int i = 0; i < SECP256_PRIVKEY_SIZE; i++) printf("%02hhx", B.private_key[i]);
    printf("\nbob public key: ");
    for (int i = 0; i < SECP256_PUBKEY_SIZE; i++) printf("%02hhx", B.public_key[i]);

    printf("\nshared secret: ");
    for (int i = 0; i < SECP256_PRIVKEY_SIZE; i++) printf("%02hhx", shared_secret[i]);

    free(A.private_key);
    free(A.public_key);
    free(B.private_key);
    free(B.public_key);

    free(shared_secret);

    printf("\n\nTesting ECDSA sign using secp256r1 and SHA2-384\n");


    struct secp_key temp_sig_key = {
        .private_key = (unsigned char*)"\xc2\x34\xf2\x54\xa5\x4d\x52\xf0\x3e\x60\x2b\xb2\x18\x19\x37\xb1\x8e\x87\x31\xf6\x20\xff\x50\x8c\xb6\xf4\x60\xe9\x58\xe8\x14\x12"
    };

    struct ECDSA_signature sig = ecdsa_sign_secp256r1(HMAC_SHA2_384, (unsigned char *)"ecdsa sign test", 15, temp_sig_key);

    printf("r: ");
    for (int i = 0; i < ECDSA_SECP256_SIG_SIZE; i++) {
        printf("%02hhx", sig.r[i]);
    }
    printf("\ns: ");
    for (int i = 0; i < ECDSA_SECP256_SIG_SIZE; i++) {
        printf("%02hhx", sig.s[i]);
    }
    printf("\n");
    free(sig.s);
    free(sig.r);

    return 0;
}