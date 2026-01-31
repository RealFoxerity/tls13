#ifndef TLS_PACKETS_H
#define TLS_PACKETS_H

#include <stddef.h>

// some simple stateless packet handlers

int encrypt_tls_packet(unsigned char wrapped_record_type, unsigned char handshake_message_type, unsigned char * __restrict out_buf, size_t out_buf_len, const unsigned char * __restrict input_buf, size_t in_buf_len);
int construct_encrypted_extensions(unsigned char * buffer, size_t len);
int construct_certificate(unsigned char * buffer, size_t len);
int construct_certificate_verify(unsigned char * buffer, size_t len);
#endif