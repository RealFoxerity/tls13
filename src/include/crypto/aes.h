#ifndef AES_H
#define AES_H

#define AES_WORD_TYPE uint32_t
#define AES_WORD_SIZE sizeof(AES_WORD_TYPE)

#define AES_128_KE_ROUNDS 10
#define AES_128_NKEY 4
#define AES_128_KEY_LEN (AES_128_NKEY*AES_WORD_SIZE)

#define AES_192_KE_ROUNDS 12
#define AES_192_NKEY 6
#define AES_192_KEY_LEN (AES_192_NKEY*AES_WORD_SIZE)

#define AES_256_KE_ROUNDS 14
#define AES_256_NKEY 8
#define AES_256_KEY_LEN (AES_256_NKEY*AES_WORD_SIZE)

#include <stdint.h>

#define AES_BLOCK_SIZE 16

void aes_128_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_128_KEY_LEN]);
void aes_128_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_128_KEY_LEN]);

void aes_192_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_192_KEY_LEN]);
void aes_192_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_192_KEY_LEN]);

void aes_256_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_256_KEY_LEN]);
void aes_256_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_256_KEY_LEN]);




void aes_128_ccm_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_128_KEY_LEN]);
void aes_128_ccm_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_128_KEY_LEN]);

void aes_192_ccm_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_192_KEY_LEN]);
void aes_192_ccm_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_192_KEY_LEN]);

void aes_256_ccm_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_256_KEY_LEN]);
void aes_256_ccm_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_256_KEY_LEN]);


void aes_128_gcm_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_128_KEY_LEN]);
void aes_128_gcm_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_128_KEY_LEN]);

void aes_192_gcm_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_192_KEY_LEN]);
void aes_192_gcm_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_192_KEY_LEN]);

void aes_256_gcm_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_256_KEY_LEN]);
void aes_256_gcm_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_256_KEY_LEN]);


#endif