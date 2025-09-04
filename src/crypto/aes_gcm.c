//https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
#include "../include/crypto/aes.h"

void aes_128_gcm_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_128_KEY_LEN]);
void aes_128_gcm_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_128_KEY_LEN]);

void aes_192_gcm_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_192_KEY_LEN]);
void aes_192_gcm_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_192_KEY_LEN]);

void aes_256_gcm_enc(const uint8_t plain_data[AES_BLOCK_SIZE], uint8_t enc_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_256_KEY_LEN]);
void aes_256_gcm_dec(const uint8_t enc_data[AES_BLOCK_SIZE],  uint8_t plain_data_out[AES_BLOCK_SIZE], const uint8_t block_cipher_key[AES_256_KEY_LEN]);
