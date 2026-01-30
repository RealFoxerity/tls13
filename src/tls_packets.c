#include "include/tls_packets.h"
#include "crypto/include/hmac.h"
#include "crypto/include/secp256.h"
#include "include/memstructs.h"
#include "include/tls_internal.h"
#include "include/tls_crypto.h"
#include "crypto/include/aes.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* https://www.rfc-editor.org/rfc/rfc8446#section-5.2
      struct {
          opaque content[TLSPlaintext.length];
          ContentType type;
          uint8 zeros[length_of_padding];
      } TLSInnerPlaintext;
      struct {
          ContentType opaque_type = application_data; // 23
          ProtocolVersion legacy_record_version = 0x0303; // TLS v1.2
          uint16 length;
          opaque encrypted_record[TLSCiphertext.length];
      } TLSCiphertext;
*/


// wrapped record type (encrypted packets end with message type), inner handshake message type (so we don't have to wrap our packets ourselves), output buffer, len, input data buffer, len
int encrypt_tls_packet(unsigned char wrapped_record_type, unsigned char handshake_message_type, unsigned char * restrict out_buf, size_t out_buf_len, const unsigned char * restrict input_buf, size_t in_buf_len) {
    assert(in_buf_len < 1<<16);
    size_t aead_tag_len = 0;
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
        case TLS_AES_256_GCM_SHA384:
            aead_tag_len = GCM_BLOCK_SIZE;
            break;
        default:
            fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            return -AD_HANDSHAKE_FAILURE;
    }

    size_t pad_bytes = 0; // selected 0 because it is not required, see https://www.rfc-editor.org/rfc/rfc8446#section-5.4
    size_t wrapped_len = sizeof(TLS_handshake) + in_buf_len + 1 + pad_bytes;
    unsigned char * input_buf_wrapped = calloc(wrapped_len, 1);
    assert(input_buf_wrapped);
    *(TLS_handshake*)input_buf_wrapped = (TLS_handshake) {
        .msg_type = handshake_message_type,
        .length = htons(in_buf_len)
    };

    memcpy(input_buf_wrapped + sizeof(TLS_handshake), input_buf, in_buf_len);
    update_transcript_hash(input_buf_wrapped, sizeof(TLS_handshake) + in_buf_len);
    input_buf_wrapped[sizeof(TLS_handshake)+in_buf_len] = wrapped_record_type;

    size_t ret_len = wrapped_len + aead_tag_len + sizeof(TLS_record_header);
    assert(out_buf_len >= ret_len);
    memset(out_buf, 0, ret_len);

    *(TLS_record_header *)out_buf = (TLS_record_header) {
        .content_type = CT_APPLICATION_DATA,
        .legacy_record_version = htons(TLS12_COMPAT_VERSION),
        .length = htons(wrapped_len + aead_tag_len)
    };

    unsigned char * nonce = NULL;
    uint8_t * ciphertext = NULL;

    // https://www.rfc-editor.org/rfc/rfc8446#section-5.2
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
        case TLS_AES_256_GCM_SHA384:
            // https://www.rfc-editor.org/rfc/rfc8446#section-5.3
            nonce = calloc(AES_GCM_DEFAULT_IV_LEN, 1); // should be max of 8 or N_MIN (in this case AES_GCM_DEFAULT_IV_LEN since AES-GCM takes any length)
            assert(nonce);
            *(uint64_t*)(nonce + AES_GCM_DEFAULT_IV_LEN - sizeof(uint64_t)) = htobe64(tls_context.txd_message_counter); // network byte order to be exact, no such thing as htonll
            for (int i = 0; i < AES_GCM_DEFAULT_IV_LEN; i++) {
                nonce[i] ^= ((uint8_t *)(tls_context.server_write_iv.data))[i];
            }
    }
    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            ciphertext = aes_128_gcm_enc(input_buf_wrapped, wrapped_len, 
                out_buf, sizeof(TLS_record_header), 
                nonce, AES_GCM_DEFAULT_IV_LEN, 
                out_buf + sizeof(TLS_record_header) + wrapped_len, 
                tls_context.server_write_key.data);
            assert(ciphertext);    
            break;
        case TLS_AES_256_GCM_SHA384:
            ciphertext = aes_256_gcm_enc(input_buf_wrapped, wrapped_len, 
                out_buf, sizeof(TLS_record_header), 
                nonce, AES_GCM_DEFAULT_IV_LEN, 
                out_buf + sizeof(TLS_record_header) + wrapped_len, 
                tls_context.server_write_key.data);
            assert(ciphertext);  
            break;
    }

    memcpy(out_buf+sizeof(TLS_record_header), ciphertext, wrapped_len);

    free(input_buf_wrapped);
    free(nonce);
    free(ciphertext);
    return ret_len;
}


int construct_encrypted_extensions(unsigned char * buffer, size_t len) {
    static const unsigned char ee_packet[] = "\x00\x00";

    int ret = encrypt_tls_packet(CT_HANDSHAKE, HT_ENCRYPTED_EXTENSIONS, buffer, len, ee_packet, sizeof(ee_packet) - 1);
    if (ret < 0) return ret;

    return ret;
}

int construct_certificate(unsigned char * buffer, size_t len) {
    size_t wrapped_cert_len = 
        sizeof(struct ServerCertificatesHeader) + 
        3 + // uint24_t for the certificate length
        tls_context.cert_len +
        2 + // uint16_t for the extension length
        0 // we don't use any extensions
    ;
    unsigned char * wrapped_cert = calloc(wrapped_cert_len, 1);
    
    assert(wrapped_cert);

    *(struct ServerCertificatesHeader*) wrapped_cert = (struct ServerCertificatesHeader) {
        .certificate_request_context = 0,
        .cert_data_len = htons(wrapped_cert_len - sizeof(struct ServerCertificatesHeader))
    };
    *(unsigned short*)&wrapped_cert[sizeof(struct ServerCertificatesHeader)+1] = htons(tls_context.cert_len); // uint24_t, need to skip the 1 byte
    memcpy(wrapped_cert + sizeof(struct ServerCertificatesHeader) + 3, tls_context.cert, tls_context.cert_len);

    // don't need to set uint16_t for extension length since they are 0 anyway

    int ret = encrypt_tls_packet(CT_HANDSHAKE, HT_CERTIFICATE, buffer, len, wrapped_cert, wrapped_cert_len);
    free(wrapped_cert);
    
    if (ret < 0) return ret;

    return ret;
}

// https://www.rfc-editor.org/rfc/rfc8446 4.4.3
#define CONTEXT_STRING "TLS 1.3, server CertificateVerify"
int construct_certificate_verify(unsigned char * buffer, size_t len) {
    enum hmac_supported_hashes chosen_hash = 0;
    switch(tls_context.chosen_signature_algo) {
        case SS_ECDSA_SECP256R1_SHA256:
            chosen_hash = HMAC_SHA2_256;
            break;
        default:
            fprintf(stderr, "Unknown/unsupported signature algorithm id %04hx\n", tls_context.chosen_signature_algo);
            return -AD_HANDSHAKE_FAILURE;
    }

    Vector hash = get_transcript_hash();
    if (hash.data == NULL) return (long)hash.len;

    unsigned char * cert_verify = malloc(64 + sizeof(CONTEXT_STRING) + hash.len);
    assert(cert_verify);
    memset(cert_verify, 0x20, 64);
    memcpy(cert_verify + 64, CONTEXT_STRING, sizeof(CONTEXT_STRING));
    
    memcpy(cert_verify + 64 + sizeof(CONTEXT_STRING), hash.data, hash.len);

    assert(tls_context.cert_keys.private_key.len == SECP256_PRIVKEY_SIZE);

    fprintf(stderr, "Signing certificateVerify:\n");
    for (int i = 0; i < 64 + sizeof(CONTEXT_STRING) + hash.len; i++) {
        fprintf(stderr, "%02hhx", cert_verify[i]);
    }

    Vector sign = asn1_wrap_secp256r1_sign(chosen_hash, cert_verify, 64 + sizeof(CONTEXT_STRING) + hash.len, (struct secp_key) {
        .private_key = tls_context.cert_keys.private_key.data
    });
    assert(sign.data);
    assert(sign.len < 1<<16);

    fprintf(stderr, "\nsignature:\n");
    for (int i = 0; i < sign.len; i++) {
        fprintf(stderr, "%02hhx", ((unsigned char *)sign.data)[i]);
    }


    unsigned char * packet_inner = malloc(
        sign.len +
        sizeof(uint16_t) + // signaturescheme
        sizeof(uint16_t) // len
    );
    assert(packet_inner);
    ((short*)packet_inner)[0] = htons(tls_context.chosen_signature_algo);
    ((short*)packet_inner)[1] = htons(sign.len);
    memcpy(packet_inner + 2 * sizeof(uint16_t), sign.data, sign.len);

    update_transcript_hash(packet_inner, sign.len + 2 * sizeof(uint16_t)); // should be safe after get_transcript_hash

    int ret = encrypt_tls_packet(CT_HANDSHAKE, HT_CERTIFICATE_VERIFY, buffer, len, packet_inner, sign.len + 2 * sizeof(uint16_t));
    free(hash.data);
    free(packet_inner);
    free(sign.data);
    free(cert_verify);

    return ret;
}