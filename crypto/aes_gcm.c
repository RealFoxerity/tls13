//https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
//https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
// for the exact case of tls 1.3 see https://www.rfc-editor.org/rfc/rfc8446#section-5.2
#include "include/aes.h"
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

typedef unsigned __int128 uint128_t;

//static inline uint128_t gcm_inc(int lower_bit_count, uint128_t string) { // implementation for 128 bit number
//    uint128_t a = string & 
//    ~(((uint128_t)1<<lower_bit_count)-1);
//
//    uint128_t b = (string+1) &
//    (((uint128_t)1<<lower_bit_count)-1);
//    
//    return a | b;
//}

static inline void gcm_inc(int lower_bit_count, uint8_t string[GCM_BLOCK_SIZE]) { // implentation for 128 bit number as an array of 16 chars in big endian
    //#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ // not needed since byte streams are always big endian
    //for (int i = 0; i < lower_bit_count/8; i++) {
    //    if (++ string[i] == 0) return; // no char overflow    
    //}
    //
    //if (lower_bit_count % 8 == 0) return;
    //
    //uint8_t temp = string[lower_bit_count/8];
    //temp ++;
    //uint8_t and_mask = 1 << (lower_bit_count % 8);
    //and_mask--;
    //string[lower_bit_count/8] = string[lower_bit_count/8] & (~and_mask);
    //string[lower_bit_count/8] |= temp & and_mask;
    //#else
    for (int i = GCM_BLOCK_SIZE - 1; i > GCM_BLOCK_SIZE - 1 - (lower_bit_count/8); i--) {
        if (++ string[i] != 0) return; // no char overflow    
    }
 
    if (lower_bit_count % 8 == 0) return;

    uint8_t temp = string[GCM_BLOCK_SIZE - 1 - (lower_bit_count/8)];
    temp ++;
    uint8_t and_mask = 1 << ((lower_bit_count % 8));
    and_mask--;
    string[GCM_BLOCK_SIZE - 1 - (lower_bit_count/8)] = string[GCM_BLOCK_SIZE - 1 - (lower_bit_count/8)] & (~and_mask);
    string[GCM_BLOCK_SIZE - 1 - (lower_bit_count/8)] |= temp & and_mask;
    //#endif
}

static const uint128_t gcm_block_mult_field_reduction_mod_mult = ((uint128_t)0b11100001) << 120; // no clue how to name
static uint128_t gcm_block_mult(uint128_t x, uint128_t y) { //see page 12 (20)
    uint128_t temp_v = y;
    uint128_t out_z = 0;
    for (int i = 0; i < 128; i++) {
        if ((x>>(127-i)) & 1) out_z ^= temp_v;
        if (temp_v & 1) {
            temp_v >>= 1;
            temp_v ^= gcm_block_mult_field_reduction_mod_mult;
        } else temp_v >>=1;
    }
    return out_z;
}


static inline uint128_t bytes_to_uint128(const uint8_t data[sizeof(uint128_t)]) {
    uint128_t out = 0;
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ // todo: test
    for (int i = 0; i < sizeof(uint128_t); i++) {
            ((uint8_t*)&out)[sizeof(uint128_t)-1-i] = data[i];
    }
    #else
        memcpy(&out, data, sizeof(uint128_t));
    #endif
    return out;
}

static inline void uint128_to_bytes(uint128_t in, uint8_t data[sizeof(uint128_t)]) {
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ // todo: test
        for (int i = 0; i < sizeof(uint128_t); i++) {
            data[i] = ((uint8_t*)&in)[sizeof(uint128_t)-1-i];
        }
    #else
        memcpy(data, &in, sizeof(uint128_t));
    #endif
}


// hash subkey H = apply cipher to bitstring 0_128
static uint128_t gcm_ghash(uint128_t hash_subkey, const uint8_t * blocks, size_t block_count) { //see page 12 (20)
    uint128_t Y = 0;
    for (int i = 0; i < block_count; i++) {
        Y = gcm_block_mult(Y^bytes_to_uint128(&blocks[i*GCM_BLOCK_SIZE]), hash_subkey);
    }
    return Y;
}

__attribute__((warn_unused_result)) static uint8_t * gcm_gctr(const uint8_t * key, int key_len, const uint8_t initial_counter_block[GCM_BLOCK_SIZE], // key size is so small, even char would suffice
        const uint8_t * bitstring, size_t bitstring_len) { //see page 13 (21)
    // implementation notes: X* can never be less than a single byte since we're operating on bytes, so point 7 is simplified
    if (bitstring_len == 0) return NULL;
    uint8_t * bitstring_out = malloc(bitstring_len+sizeof(uint128_t));
    assert(bitstring_out);
    memset(bitstring_out, 0, bitstring_len);

    size_t n = bitstring_len/GCM_BLOCK_SIZE + ((bitstring_len%GCM_BLOCK_SIZE) == 0? 0:1);

    uint8_t cb[GCM_BLOCK_SIZE] = {0};
    memcpy(cb, initial_counter_block, GCM_BLOCK_SIZE);

    uint8_t temp_block[GCM_BLOCK_SIZE] = {0};

    for (int i = 0; i < n-1; i++) {
        switch (key_len) {
            case AES_128_KEY_LEN:
                aes_128_enc(cb, temp_block, key);
                break;
            case AES_192_KEY_LEN:
                aes_192_enc(cb, temp_block, key);
                break;
            case AES_256_KEY_LEN:
                aes_256_enc(cb, temp_block, key);
                break;
            default:
                fprintf(stderr, "Key size %d is not allowable for this algorithm\n", key_len);
                exit(-1);
        }
        ((uint128_t*)(bitstring_out))[i] = ((uint128_t*)(bitstring))[i] ^ (*(uint128_t*)temp_block); 
            // quick way to do 128 bit xor, uint128_t here because GCM and AES block is 128 bits, TODO: rewrite for better clarity
        gcm_inc(32, cb);
    }

    uint8_t temp_block_x[GCM_BLOCK_SIZE] = {0}; // the simplified point 7
    memcpy(temp_block_x, &bitstring[(n-1)*GCM_BLOCK_SIZE], (bitstring_len%GCM_BLOCK_SIZE == 0 )? GCM_BLOCK_SIZE:(bitstring_len%GCM_BLOCK_SIZE));

    switch (key_len) {
        case AES_128_KEY_LEN:
            aes_128_enc(cb, temp_block, key);
            break;
        case AES_192_KEY_LEN:
            aes_192_enc(cb, temp_block, key);
            break;
        case AES_256_KEY_LEN:
            aes_256_enc(cb, temp_block, key);
            break;
        //default:
        //    fprintf(stderr, "Key size %d is not allowable for this algorithm\n", key_size);
        //    exit(-1);
    }
    ((uint128_t*)(bitstring_out))[n-1] = (*(uint128_t*)temp_block_x) ^ (*(uint128_t*)temp_block); 

    return bitstring_out;
}

static void aes_prepare(uint8_t * subkey, const uint8_t * key, size_t key_len, const uint8_t * IV, size_t IV_len, uint8_t * pre_counter_block) {
    uint8_t tempblock[GCM_BLOCK_SIZE] = {0};
    switch (key_len) {
        case AES_128_KEY_LEN:
            aes_128_enc(tempblock, subkey, key);
            break;
        case AES_192_KEY_LEN:
            aes_192_enc(tempblock, subkey, key);
            break;
        case AES_256_KEY_LEN:
            aes_256_enc(tempblock, subkey, key);
            break;
        default:
            fprintf(stderr, "Key size %lu is not allowable for this algorithm\n", key_len);
            exit(-1);
    }

    if (IV_len == AES_GCM_DEFAULT_IV_LEN) { // see page 15(23)
        memcpy(pre_counter_block, IV, IV_len);
        pre_counter_block[GCM_BLOCK_SIZE - 1] |= 1;
    } else {
        size_t padding_bytes = GCM_BLOCK_SIZE*(IV_len/GCM_BLOCK_SIZE + (IV_len%GCM_BLOCK_SIZE != 0?1:0)) - IV_len;

        uint8_t * padded_iv = malloc(IV_len + padding_bytes + GCM_BLOCK_SIZE);
        assert(padded_iv);
        memset(padded_iv, 0, IV_len + padding_bytes + GCM_BLOCK_SIZE);

        memcpy(padded_iv, IV, IV_len);

        *(uint64_t*)&padded_iv[IV_len + padding_bytes + sizeof(uint64_t)] = htobe64(IV_len*8); // BITS

        uint128_t pcb_temp = gcm_ghash(bytes_to_uint128(subkey), padded_iv, (IV_len + padding_bytes + GCM_BLOCK_SIZE)/GCM_BLOCK_SIZE);
        free(padded_iv);
        uint128_to_bytes(pcb_temp, pre_counter_block);
    }
}

__attribute__((warn_unused_result)) static uint8_t * aes_gcm_authenticate_encryption_internal( // returns ciphertext, writes auth_tag to auth_tag_out
        const uint8_t * plaintext, size_t data_len,
        const uint8_t * key, size_t key_len,
        const uint8_t * additional_auth_data, size_t aad_len, 
        const uint8_t * IV, size_t IV_len, 
        uint8_t auth_tag_out[GCM_BLOCK_SIZE], size_t auth_tag_len) { // tag len values depend on gcm mode
    uint8_t subkey[GCM_BLOCK_SIZE] = {0}; // subhash, H
    uint8_t pre_counter_block[GCM_BLOCK_SIZE] = {0}; // J0, Y0 in second source
    uint8_t pre_counter_block_2[GCM_BLOCK_SIZE] = {0}; // gcm_gctr for auth tag needs original PCB, inc before ciphertext breaks auth tag
    
    aes_prepare(subkey, key, key_len, IV, IV_len, pre_counter_block);
    memcpy(pre_counter_block_2, pre_counter_block, GCM_BLOCK_SIZE);

    uint8_t tempblock[GCM_BLOCK_SIZE] = {0};


    gcm_inc(32, pre_counter_block);
    uint8_t * ciphertext = gcm_gctr(key, key_len, pre_counter_block, plaintext, data_len);
    assert(ciphertext || data_len == 0);

    size_t data_pad_blocks = GCM_BLOCK_SIZE * (data_len/GCM_BLOCK_SIZE + (data_len%GCM_BLOCK_SIZE != 0?1:0)) - data_len;
    size_t aad_pad_blocks = GCM_BLOCK_SIZE * (aad_len/GCM_BLOCK_SIZE + (aad_len%GCM_BLOCK_SIZE != 0?1:0)) - aad_len;

    uint8_t * block_s_in = malloc(aad_len + data_len + data_pad_blocks + aad_pad_blocks + GCM_BLOCK_SIZE); // GCM_BLOCK_SIZE is 2 64bit numbers, see page 15(23) step 5
    assert(block_s_in);

    memset(block_s_in, 0, aad_len + data_len + data_pad_blocks + aad_pad_blocks + GCM_BLOCK_SIZE);
    memcpy(block_s_in, additional_auth_data, aad_len);
    memcpy(block_s_in + aad_len + aad_pad_blocks, ciphertext, data_len);

    *(uint64_t*)(block_s_in + aad_len + aad_pad_blocks + data_len + data_pad_blocks) = htobe64(aad_len*8); // len is in BITS !!!!
    *(uint64_t*)(block_s_in + aad_len + aad_pad_blocks + data_len + data_pad_blocks + sizeof(uint64_t)) = htobe64(data_len*8);

    uint128_t block_s = gcm_ghash(bytes_to_uint128(subkey), block_s_in, (aad_len + data_len + data_pad_blocks + aad_pad_blocks + GCM_BLOCK_SIZE)/GCM_BLOCK_SIZE);
    uint128_to_bytes(block_s, tempblock);
    free(block_s_in);

    uint8_t * tag = gcm_gctr(key, key_len, pre_counter_block_2, tempblock, GCM_BLOCK_SIZE);
    
    memcpy(auth_tag_out, tag, auth_tag_len);
    free(tag);
    return ciphertext;
}  
__attribute__((warn_unused_result)) static uint8_t * aes_gcm_authenticate_decryption_internal ( // returns FAIL code, basically the exact same thing as ^ but checks the tag and S is different, todo: refactor
        const uint8_t * ciphertext, size_t data_len,
        const uint8_t * key, size_t key_len,
        const uint8_t * additional_auth_data, size_t aad_len, 
        const uint8_t * IV, size_t IV_len, 
        const uint8_t auth_tag[GCM_BLOCK_SIZE], size_t auth_tag_len) {
    uint8_t subkey[GCM_BLOCK_SIZE] = {0}; // subhash, H
    uint8_t pre_counter_block[GCM_BLOCK_SIZE] = {0}; // J0, Y0 in second source
    uint8_t pre_counter_block_2[GCM_BLOCK_SIZE] = {0}; // gcm_gctr for auth tag needs original PCB, inc before ciphertext breaks auth tag
    uint8_t tempblock[GCM_BLOCK_SIZE] = {0};

    aes_prepare(subkey, key, key_len, IV, IV_len, pre_counter_block);
    memcpy(pre_counter_block_2, pre_counter_block, GCM_BLOCK_SIZE);

    gcm_inc(32, pre_counter_block);
    uint8_t * plaintext = gcm_gctr(key, key_len, pre_counter_block, ciphertext, data_len);
    if (plaintext == NULL && data_len != 0) return (uint8_t*)-1; // the fail code
    
    size_t data_pad_blocks = GCM_BLOCK_SIZE * (data_len/GCM_BLOCK_SIZE + (data_len%GCM_BLOCK_SIZE != 0?1:0)) - data_len;
    size_t aad_pad_blocks = GCM_BLOCK_SIZE * (aad_len/GCM_BLOCK_SIZE + (aad_len%GCM_BLOCK_SIZE != 0?1:0)) - aad_len;

    uint8_t * block_s_in = malloc(aad_len + data_len + data_pad_blocks + aad_pad_blocks + GCM_BLOCK_SIZE); // GCM_BLOCK_SIZE is 2 64bit numbers, see page 15(23) step 5
    assert(block_s_in);

    memset(block_s_in, 0, aad_len + data_len + data_pad_blocks + aad_pad_blocks + GCM_BLOCK_SIZE);
    memcpy(block_s_in, additional_auth_data, aad_len);
    memcpy(block_s_in + aad_len + aad_pad_blocks, ciphertext, data_len);

    *(uint64_t*)(block_s_in + aad_len + aad_pad_blocks + data_len + data_pad_blocks) = htobe64(aad_len*8); // len is in BITS !!!!
    *(uint64_t*)(block_s_in + aad_len + aad_pad_blocks + data_len + data_pad_blocks + sizeof(uint64_t)) = htobe64(data_len*8);

    uint128_t block_s = gcm_ghash(bytes_to_uint128(subkey), block_s_in, (aad_len + data_len + data_pad_blocks + aad_pad_blocks + GCM_BLOCK_SIZE)/GCM_BLOCK_SIZE);
    uint128_to_bytes(block_s, tempblock);
    free(block_s_in);

    uint8_t * tag = gcm_gctr(key, key_len, pre_counter_block_2, tempblock, GCM_BLOCK_SIZE);
    if (memcmp(tag, auth_tag, GCM_BLOCK_SIZE) != 0) {
        free(tag);
        free(plaintext);
        return NULL;
    }
    free(tag);
    return plaintext;
}

__attribute__((warn_unused_result)) uint8_t * aes_128_gcm_enc(const uint8_t * plain_data, size_t data_len, const uint8_t * AAD, size_t aad_len, const uint8_t * IV, size_t iv_len, uint8_t auth_tag_out[GCM_BLOCK_SIZE], const uint8_t block_cipher_key[AES_128_KEY_LEN]) {
    return aes_gcm_authenticate_encryption_internal(plain_data, data_len, block_cipher_key, AES_128_KEY_LEN, AAD, 
        aad_len, IV, iv_len, auth_tag_out, GCM_BLOCK_SIZE);
}
__attribute__((warn_unused_result)) uint8_t * aes_128_gcm_dec(const uint8_t * ciphertext, size_t data_len, const uint8_t * AAD, size_t aad_len, const uint8_t * IV, size_t iv_len, const uint8_t * auth_tag_in, const uint8_t block_cipher_key[AES_128_KEY_LEN]) {
    return aes_gcm_authenticate_decryption_internal(ciphertext, data_len, block_cipher_key, AES_128_KEY_LEN, AAD, aad_len, IV, iv_len, auth_tag_in, GCM_BLOCK_SIZE);
}

__attribute__((warn_unused_result)) uint8_t * aes_192_gcm_enc(const uint8_t * plain_data, size_t data_len, const uint8_t * AAD, size_t aad_len, const uint8_t * IV, size_t iv_len, uint8_t auth_tag_out[GCM_BLOCK_SIZE], const uint8_t block_cipher_key[AES_192_KEY_LEN]) {
    return aes_gcm_authenticate_encryption_internal(plain_data, data_len, block_cipher_key, AES_192_KEY_LEN, AAD, 
        aad_len, IV, iv_len, auth_tag_out, GCM_BLOCK_SIZE);
}
__attribute__((warn_unused_result)) uint8_t * aes_192_gcm_dec(const uint8_t * ciphertext, size_t data_len, const uint8_t * AAD, size_t aad_len, const uint8_t * IV, size_t iv_len, const uint8_t * auth_tag_in, const uint8_t block_cipher_key[AES_192_KEY_LEN]) {
    return aes_gcm_authenticate_decryption_internal(ciphertext, data_len, block_cipher_key, AES_192_KEY_LEN, AAD, aad_len, IV, iv_len, auth_tag_in, GCM_BLOCK_SIZE);
}
__attribute__((warn_unused_result)) uint8_t * aes_256_gcm_enc(const uint8_t * plain_data, size_t data_len, const uint8_t * AAD, size_t aad_len, const uint8_t * IV, size_t iv_len, uint8_t auth_tag_out[GCM_BLOCK_SIZE], const uint8_t block_cipher_key[AES_256_KEY_LEN]) {
    return aes_gcm_authenticate_encryption_internal(plain_data, data_len, block_cipher_key, AES_256_KEY_LEN, AAD, 
        aad_len, IV, iv_len, auth_tag_out, GCM_BLOCK_SIZE);
}
__attribute__((warn_unused_result)) uint8_t * aes_256_gcm_dec(const uint8_t * ciphertext, size_t data_len, const uint8_t * AAD, size_t aad_len, const uint8_t * IV, size_t iv_len, const uint8_t * auth_tag_in, const uint8_t block_cipher_key[AES_256_KEY_LEN]) {
        return aes_gcm_authenticate_decryption_internal(ciphertext, data_len, block_cipher_key, AES_256_KEY_LEN, AAD, aad_len, IV, iv_len, auth_tag_in, GCM_BLOCK_SIZE);
}