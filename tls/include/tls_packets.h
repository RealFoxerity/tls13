#ifndef TLS_PACKETS_H
#define TLS_PACKETS_H

#include "tls_internal.h"
#include <stddef.h>

// some simple stateless packet handlers

int encrypt_tls_packet(struct tls_context * tls_context, unsigned char wrapped_record_type, unsigned char handshake_message_type, unsigned char * __restrict out_buf, size_t out_buf_len, const unsigned char * __restrict input_buf, size_t in_buf_len);
int decrypt_tls_packet(struct tls_context * tls_context, unsigned char ** out_buf, unsigned char * in_buf, size_t in_buf_len, size_t record_end_offset, TLS_handshake * handshake_hdr_out, unsigned char * wrapped_type_out);

int construct_encrypted_extensions(struct tls_context * tls_context, unsigned char * buffer, size_t len);
int construct_certificate(struct tls_context * tls_context, unsigned char * buffer, size_t len);
int construct_certificate_verify(struct tls_context * tls_context, unsigned char * buffer, size_t len);
int construct_server_finished(struct tls_context * tls_context, unsigned char * buffer, size_t len);

int verify_client_finished(struct tls_context * tls_context, unsigned char * buffer, size_t len); // takes in decrypted buffer
#endif