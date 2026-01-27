#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> // malloc, free
#include <assert.h>
#include <netinet/in.h> // sockaddr_in, htons
#include <sys/select.h>
#include <sys/socket.h> // recv, setsockopt
#include <time.h> // ctime
#include <sys/wait.h>

#include <string.h> // memset, strncmp

#include <errno.h>

#include <unistd.h> // close, access

#include "crypto/include/aes.h"
#include "http/include/server.h"
#include "include/tls.h"
#include "include/tls_extensions.h"
#include "include/memstructs.h"
#include "crypto/include/sha2.h"
#include "include/tls_crypto.h"

#define MIN(a,b) (a>b?b:a)
#define MAX(a,b) (a<b?b:a)

// TODO: find time to rewrite most of htons to htobe16 for clarity

// targetting TLS v1.3, no compatibility mode based on https://www.rfc-editor.org/rfc/rfc8446

int inner_fd = -1; // socket TLS-application

extern char * real_root; // since we fork for a second time, we need to manually free real_root otherwise we leak up to PATH_MAX (4096) bytes
extern unsigned char * ssl_cert;
extern size_t ssl_cert_len;
char * target_server_name = NULL;

struct tls_context tls_context = {0};

//Vector pkem = {0}; // pkem enum
//Vector pre_shared_key = {0};

unsigned char * tls_packet_buffer = NULL;

enum tls_state current_state = TS_SETTING_UP_INTERACTIVE;

size_t print_hex_buf(const unsigned char * buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            if (i != 0) fprintf(stderr, "\n");
            fprintf(stderr, "%04lx ", i);
        }
        fprintf(stderr, "%02hhx ", buf[i]);
    }
    fprintf(stderr, "\n");
    return len;
}

//#define recv(fd, buf, len, fl) print_hex_buf(buf, recv(fd, buf, len, fl))
//#define send(fd, buf, len, fl) {fprintf(stderr, "Txd:\n"); print_hex_buf(buf, len); send(fd, buf, len, fl);}

void cleanup();
void free_tls_metadata() {
    cleanup();
    free(tls_packet_buffer);
    free(real_root);
}

int decrypt_tls(unsigned char* buffer, size_t len);
int encrypt_tls_packet(unsigned char wrapped_record_type, unsigned char original_packet_type, unsigned char * restrict out_buf, size_t out_buf_len, const unsigned char * restrict input_buf, size_t in_buf_len);
void construct_alert(unsigned char alert_desc, unsigned char alert_level, unsigned char* buffer, size_t bufsiz) {
    assert(bufsiz >= sizeof(TLS_record_header)+sizeof(struct Alert));
    memset(buffer, 0, bufsiz);
    ((TLS_record_header*)buffer)->content_type = CT_ALERT;
    ((TLS_record_header*)buffer)->legacy_record_version = htons(TLS11_COMPAT_VERSION);
    ((TLS_record_header*)buffer)->length = htons(2);
    ((struct Alert*)(buffer+sizeof(TLS_record_header)))->alert_level = alert_level;
    ((struct Alert*)(buffer+sizeof(TLS_record_header)))->alert_description = alert_desc;
}

int construct_encrypted_extensions(unsigned char * buffer, size_t len);
int construct_certificate(unsigned char * buffer, size_t len);

void exit_handler(int signal) {
    fprintf(stderr, "Caught Ctrl+C, exiting ssl wrapper\n");
    free_tls_metadata();

    shutdown(inner_fd, SHUT_RDWR);
    close(inner_fd);
    while(wait(NULL) != -1); // wait for all child processes

    exit(EXIT_SUCCESS);
}

char ssl_wrapper(int socket_fd, void (*wrapped_func)(int socket_fd)) {
    signal(SIGINT, exit_handler);
    int socks[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, socks) == 0);

    inner_fd = socks[0];
    switch (fork()) {
        case 0:
            close(socks[0]);
            wrapped_func(socks[1]);
            return(EXIT_SUCCESS);
            break;
        default:
            close(socks[1]);
            break;
    }

    fd_set set;
    FD_ZERO(&set);

    FD_SET(socket_fd, &set);
    FD_SET(inner_fd, &set);
    errno = 0;

    tls_packet_buffer = malloc(MAX_REQUEST_SIZE);
    assert(tls_packet_buffer!=NULL);

    int recv_len = 0;

    int ret;
    current_state = TS_SETTING_UP_INTERACTIVE;

    while (select(MAX(socket_fd, inner_fd)+1, &set, NULL, NULL, NULL) != -1) {
        if (FD_ISSET(socket_fd, &set)) { // client sending a message
            tls_context.recv_message_counter ++;
            FD_SET(inner_fd, &set);
            //fprintf(stderr, "Recv:\n");
            recv_len = recv(socket_fd, tls_packet_buffer, MAX_REQUEST_SIZE, 0);
            if (recv_len == 0) continue; // how?

            if ((ret = decrypt_tls(tls_packet_buffer, recv_len)) == 0xFFFFFFFF) { // got alert
                free_tls_metadata();
                return EXIT_FAILURE;
            } else if (ret < 0) {
                alert:
                construct_alert(-ret, AL_FATAL, tls_packet_buffer, MAX_REQUEST_SIZE);
                send(socket_fd, tls_packet_buffer, sizeof(TLS_record_header)+sizeof(struct Alert), 0); // alert messages are always 7 bytes long
                free_tls_metadata();
                return (EXIT_FAILURE);
            } else if (ret == 0) continue; // packet doesn't require an answer
            else {
                switch (current_state) {
                    case TS_READY:
                        tls_context.txd_message_counter ++;
                        send(inner_fd, tls_packet_buffer, ret, 0);
                        break;
                    case TS_SETTING_UP_INTERACTIVE: // during back and forth between client and server (client hello -> server hello...)
                        tls_context.txd_message_counter ++;
                        send(socket_fd, tls_packet_buffer, ret, 0);
                        break;
                    case TS_SETTING_UP_SERVER_SIDE: // sending the actual server hello, change cipher spec, wrapped records, encrypted extensions
                        send(socket_fd, tls_packet_buffer, ret, 0);
                        ret = construct_encrypted_extensions(tls_packet_buffer, MAX_REQUEST_SIZE);
                        if (ret < 0) goto alert;
                        tls_context.txd_message_counter ++;
                        send(socket_fd, tls_packet_buffer, ret, 0);
                        ret = construct_certificate(tls_packet_buffer, MAX_REQUEST_SIZE);
                        if (ret < 0) goto alert;
                        tls_context.txd_message_counter ++;
                        send(socket_fd, tls_packet_buffer, ret, 0);
                        // certificate verify
                    default:
                        break;
                }
            }
        
        } else { // server sending a message
            tls_context.txd_message_counter ++;
            FD_SET(socket_fd, &set);
            recv_len = recv(inner_fd, tls_packet_buffer, MAX_REQUEST_SIZE, 0);
            //encrypt_tls(buffer, recv_len);
            send(socket_fd, tls_packet_buffer, recv_len, 0);
        }
    }
    perror("TLS wrapper select(): ");
    close(inner_fd);
    close(socket_fd);
    free_tls_metadata();
    
    return (errno == EINTR?EXIT_SUCCESS:EXIT_FAILURE);
}


void parse_client_hello(unsigned char * buffer, size_t len, struct ClientHello * CH) { // TODO: add human readable errors and valid alerts
    size_t message_offset = 0;
    
    CH->legacy_session_id.len = buffer[message_offset];
    CH->legacy_session_id.data = malloc(CH->legacy_session_id.len);
    assert(CH->legacy_session_id.data != NULL);
    assert(message_offset+CH->legacy_session_id.len+1<=len);
    memset(CH->legacy_session_id.data, 0, CH->legacy_session_id.len);
    memcpy(CH->legacy_session_id.data, buffer+message_offset+1, CH->legacy_session_id.len);
    
    message_offset += 1 + CH->legacy_session_id.len;

    CH->cipher_suites.len = htons(*(unsigned short*)&buffer[message_offset]);
    assert(CH->cipher_suites.len >= 2 && CH->cipher_suites.len % 2 == 0);
    CH->cipher_suites.data = malloc(CH->cipher_suites.len);
    assert(CH->cipher_suites.data != NULL);
    assert(message_offset+CH->cipher_suites.len+2 <= len);
    memcpy(CH->cipher_suites.data, buffer+message_offset+2, CH->cipher_suites.len);
    message_offset += 2 + CH->cipher_suites.len;

    CH->legacy_compression_methods.len = buffer[message_offset];
    assert(CH->legacy_compression_methods.len >= 1);
    CH->legacy_compression_methods.data = malloc(CH->legacy_compression_methods.len);
    assert(CH->legacy_compression_methods.data != NULL);
    assert(message_offset+CH->legacy_compression_methods.len+1 <= len);
    memcpy(CH->legacy_compression_methods.data, buffer+message_offset+1, CH->legacy_compression_methods.len);
    message_offset += 1 + CH->legacy_compression_methods.len;
    assert(CH->legacy_compression_methods.len == 1 && *(char*)(CH->legacy_compression_methods.data) == 0x00 && "TLS v1.3 specifies compression method should be NULL");

    CH->extensions.len = htons(*(short*)&buffer[message_offset]);
    assert(CH->extensions.len >= 8);
    CH->extensions.data = malloc(CH->extensions.len);
    assert(CH->extensions.data != NULL);
    assert(message_offset+CH->extensions.len+2 <= len);
    memcpy(CH->extensions.data, buffer+message_offset+2, CH->extensions.len);
    message_offset += 2 + CH->extensions.len;
    
    fprintf(stderr, "CH: LSI: %hhu CS: %hu LCM: %hu EXT: %hu\n", CH->legacy_session_id.len, CH->cipher_suites.len, CH->legacy_compression_methods.len, CH->extensions.len);
}

int parse_extensions(struct ClientHello CH) { // TODO: parse extentions .... :D
    Vector supported_groups = {0}; // namedgroups enum
    Vector signature_algorithms = {0}; // signatureschemes enum
    KeyShares key_shares = {0}; // namedgroups enum, key_exchange vector

    char found_ver = 0;
    unsigned short len, ext;
    for (int i = 0; i<CH.extensions.len;) {
        ext = htons(*(unsigned short*)&((unsigned char*)CH.extensions.data)[i]);
        i+=2;
        len = htons(*(unsigned short*)&((unsigned char*)CH.extensions.data)[i]);
        i+=2;
        if (len > CH.extensions.len) return AD_DECODE_ERROR;
        switch (ext) {
            case ET_PADDING:
                break;
            case ET_SIGNATURE_ALGORITHMS: // alert missing_extension
                signature_algorithms = parse_signature_algorithms_extension(&((unsigned char*)CH.extensions.data)[i], len);
                if (signature_algorithms.data == NULL) {
                    fprintf(stderr, "Found SIGNATURE_ALGORITHMS ext, but values are invalid/missing!\n");
                    return -AD_ILLEGAL_PARAMETER;
                }
                fprintf(stderr, "Found SIGNATURE_ALGORITHMS extension\n");
                for (int i = 0; i < signature_algorithms.len / 2; i++) { // /2 because unsigned short - 2 bytes 
                    fprintf(stderr, "Client reports supported signature algorithm 0x%04hx\n", htons(((unsigned short*)signature_algorithms.data)[i]));
                }
                break;
            case ET_SUPPORTED_VERSIONS: // against RFC, but since we dont support anything other than 1.3, alert missing_extension
                if (parse_supported_versions_extension(&((unsigned char*)CH.extensions.data)[i], len) == 1) {
                    fprintf(stderr, "Bravo, the client indicated with a TLS 1.3 exclusive extension that it does not support TLS 1.3\n");
                    return -AD_ILLEGAL_PARAMETER;
                }
                fprintf(stderr, "Found SUPPORTED_VERSIONS extension: TLS 1.3 supported\n");
                found_ver = 1;
                break;
            case ET_SERVER_NAME: // alert missing_extension
                if ((target_server_name = parse_server_name_extension(&((unsigned char*)CH.extensions.data)[i], len)) == NULL) {
                    fprintf(stderr, "Found SERVER_NAME ext, but values are invalid!\n");
                    return -AD_ILLEGAL_PARAMETER;
                }
                fprintf(stderr, "Found SERVER_NAME extension: %s\n", target_server_name);
                break;
            case ET_SUPPORTED_GROUPS:
                supported_groups = parse_supported_groups_extension(&((unsigned char*)CH.extensions.data)[i], len);
                if (supported_groups.data == NULL) {
                    fprintf(stderr, "Found SUPPORTED_GROUPS extension, but values are invalid/missing!\n");
                    return -AD_ILLEGAL_PARAMETER;
                }
                fprintf(stderr, "Found SUPPORTED_GROUPS extension\n");
                for (int i = 0; i < supported_groups.len / 2; i++) { // /2 because unsigned short - 2 bytes 
                    fprintf(stderr, "Client reports supported key exchange group 0x%04hx\n", htons(((unsigned short*)supported_groups.data)[i]));
                }
                break;
            case ET_KEY_SHARE:
                key_shares = parse_key_share_groups_extension(&((unsigned char*)CH.extensions.data)[i], len);
                if (key_shares.node.key_exchange.data == NULL) {
                    fprintf(stderr, "Found KEY_SHARE extension, but values are invalid/missing!\n");
                    return -AD_ILLEGAL_PARAMETER;
                }
                fprintf(stderr, "Found KEY_SHARE extension\n");
                break;
            //case ET_PSK_KEY_EXCHANGE_MODES:
            //    pkem = parse_psk_key_exchange_modes_extension(&((unsigned char*)CH.Extension.data)[i], len);
            //    if (pkem.data == NULL) {
            //        fprintf(stderr, "Found ET_PSK_KEY_EXCHANGE_MODES extension, but values are invalid/missing!\n");
            //        return AD_ILLEGAL_PARAMETER;
            //    }
            //    fprintf(stderr, "Found ET_PSK_KEY_EXCHANGE_MODES extension\n");
            //    break;
            case ET_SESSION_TICKET_IGNORE:
                fprintf(stderr, "Found SESSION_TICKET extension\n");
                break;
            
            default:
                fprintf(stderr, "Unknown extension id: %hx\n", ext);
        }
        i+=len;
    }
    
    if (!found_ver || signature_algorithms.data == NULL || supported_groups.data == NULL || key_shares.node.group == 0) { // || (pre_shared_key.data != NULL && pkem.data == NULL)) {
        return -AD_MISSING_EXTENSION;
    }

    if (supported_groups.data == NULL) {
        return -AD_MISSING_EXTENSION; // no clue if actually according to spec, nothing there, but SG seems important so idk
    }
    for (int i = 0; i < supported_groups.len/2; i++) {
        if (((short*)supported_groups.data)[i] == htons(NG_SECP256R1)) {
            tls_context.chosen_group = NG_SECP256R1;
        }
    }
    free(supported_groups.data);

    for (int i = 0; i < signature_algorithms.len/2; i++) {
        if (((short*)signature_algorithms.data)[i] == htons(SS_ECDSA_SECP256R1_SHA256)) {
            tls_context.chosen_signature_algo = SS_ECDSA_SECP256R1_SHA256;
        }
    }
    free(signature_algorithms.data);

    KeyShares *curr = &key_shares;
    printf("Client provided supported key shares:\n");
    do {
        printf("%04hx\n", curr->node.group);
        if (curr->node.group == NG_SECP256R1) {
            tls_context.client_key_share = curr->node;
            //break;
        }
    } while ((curr = curr->next) != NULL);

    curr = &key_shares; // cleanup key_shares
    KeyShares prev = {0};
    prev = key_shares;
    do {
        prev = *curr;
        if (curr->node.key_exchange.data != tls_context.client_key_share.key_exchange.data) // for some reason can't do curr->node != chosen_key_share
            free(curr->node.key_exchange.data);
        if (curr != &key_shares) {
            free(curr);
        };
    } while ((curr = prev.next) != NULL);

    for (int i = 0; i < CH.cipher_suites.len/2; i++) {
        switch (htons(((short*)CH.cipher_suites.data)[i])) {
            case TLS_AES_256_GCM_SHA384:
                tls_context.chosen_cipher_suite = TLS_AES_256_GCM_SHA384;
                goto have_aes256; // we prefer aes256-gcm-sha384
                break;
            case TLS_AES_128_GCM_SHA256:
                tls_context.chosen_cipher_suite = TLS_AES_128_GCM_SHA256;
                break;
        }
    }
    have_aes256:

    if (tls_context.chosen_signature_algo == 0) {
        printf("No mutually supported signature algorithms\n");
        return -AD_HANDSHAKE_FAILURE;
    }

    if (tls_context.client_key_share.group == 0) {
        printf("No mutually supported key share algorithms\n");
        return -AD_HANDSHAKE_FAILURE;
    }

    if (tls_context.chosen_group == 0) {
        printf("No mutually supported named groups\n");   
        return -AD_HANDSHAKE_FAILURE;
    }

    if (tls_context.chosen_cipher_suite == 0) {
        printf("No mutually supported cipher suites\n");
        return -AD_HANDSHAKE_FAILURE;
    }

    return 1;
}

void free_client_hello(struct ClientHello CH) {
    free(CH.cipher_suites.data);
    free(CH.extensions.data);
    free(CH.legacy_compression_methods.data);
    free(CH.legacy_session_id.data);
}

int construct_server_hello(unsigned char * buffer, size_t len, struct ClientHello CH, char is_retry_request) {
    if (/* is_retry_request && */ tls_context.chosen_cipher_suite == 0) { // implicitally is_retry_request since otherwise ccs wouldn't be 0
        tls_context.chosen_cipher_suite = TLS_AES_256_GCM_SHA384;
    }
        
    if (tls_context.chosen_group == 0) {
        tls_context.chosen_group = NG_SECP256R1;
    }

    if (is_retry_request) {
        unsigned char * special_mes = NULL;
        switch (tls_context.chosen_cipher_suite) {
            case TLS_AES_128_GCM_SHA256:                
                // see https://www.rfc-editor.org/rfc/rfc8446#section-4.4.1
                special_mes = calloc(sizeof(TLS_handshake) + SHA256_HASH_BYTES, 1);
                assert(special_mes);

                (*(TLS_handshake*)special_mes).msg_type = HT_MESSAGE_HASH;
                (*(TLS_handshake*)special_mes).length = htons(SHA256_HASH_BYTES);
                sha256_finalize(&tls_context.transcript_hash_ctx, special_mes + sizeof(TLS_handshake));
                sha256_init(&tls_context.transcript_hash_ctx);
                sha256_update(&tls_context.transcript_hash_ctx, special_mes, sizeof(TLS_handshake) + SHA256_HASH_BYTES);
                break;
            case TLS_AES_256_GCM_SHA384:
                special_mes = calloc(sizeof(TLS_handshake) + SHA384_HASH_BYTES, 1);
                assert(special_mes);

                (*(TLS_handshake*)special_mes).msg_type = HT_MESSAGE_HASH;
                (*(TLS_handshake*)special_mes).length = htons(SHA384_HASH_BYTES);
                sha384_finalize(&tls_context.transcript_hash_ctx, special_mes + sizeof(TLS_handshake));
                sha384_init(&tls_context.transcript_hash_ctx);
                sha384_update(&tls_context.transcript_hash_ctx, special_mes, sizeof(TLS_handshake) + SHA384_HASH_BYTES);
                break;
            default:
                fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
                return -AD_HANDSHAKE_FAILURE;
        }
        free(special_mes);
    }
    
    size_t extensions_len = 0;  // we dont't have any encrypted extensions
    //must respond to supported_versions, key_share
    extensions_len += 2+2+2; // 2 supported versions extension id, 2 size, 2 supported version
    extensions_len += 2+2+2+(is_retry_request==0?(2+tls_context.client_key_share.key_exchange.len):0); // 2 key_share extension id, 2 size, 2 chosen algo, 2 public key len, public key
        
    //extensions_len += ((is_retry_request && tls_context.chosen_signature_algo == 0)?(2+2+2+2):0); // not supported, look below - 2 signature_algo id, 2 size, 2 preferred algo vec size, 2 preferred algo

    size_t final_size = 
    sizeof(TLS_record_header) +
    sizeof(TLS_handshake) + 
    2 + // version
    TLS_RANDOM_LEN +
    1 + CH.legacy_session_id.len + 
    2 + // cipher suite
    1 + // legacy compression
    2 + extensions_len;

    assert(final_size <= (1<<16)-1);
    assert(final_size <= len);

    memset(buffer, 0, len);

    *(TLS_record_header *)buffer = (TLS_record_header) {
        .content_type = CT_HANDSHAKE,
        .legacy_record_version = htons(TLS12_COMPAT_VERSION),
        .length = htons(final_size-sizeof(TLS_record_header))
    };

    size_t bufoff = sizeof(TLS_record_header);

    ((TLS_handshake*)(buffer+bufoff))->msg_type = HT_SERVER_HELLO;
    ((TLS_handshake*)(buffer+bufoff))->length = htons(final_size-sizeof(TLS_handshake)-sizeof(TLS_record_header));

    bufoff += sizeof(TLS_handshake);
    *(short*)(buffer+bufoff) = TLS12_COMPAT_VERSION;
    bufoff += 2;

    if (!is_retry_request) {
        srandom(time(NULL));
        for (int i =0; i < 8; i++) { // get random for server random field TODO: FIX!!! HAVE TO USE CSPRNG
            ((int*)(buffer+bufoff))[i] = random();
        }
        memcpy(tls_context.random_crypto, buffer+bufoff, TLS_RANDOM_LEN);
    } else {
        memcpy(buffer+bufoff, TLS_SERVER_HELLO_RETRY_REQUEST_MAGIC, TLS_RANDOM_LEN);
    }
    bufoff += TLS_RANDOM_LEN;

    buffer[bufoff] = CH.legacy_session_id.len;
    bufoff ++;

    memcpy(buffer+bufoff, CH.legacy_session_id.data, CH.legacy_session_id.len);
    bufoff += CH.legacy_session_id.len;

    *(short*)(buffer+bufoff) = htons(tls_context.chosen_cipher_suite);
    bufoff +=2;

    buffer[bufoff] = 0; // null (no) compression
    bufoff ++;

    *(short*)&(buffer[bufoff]) = htons(extensions_len);
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(ET_SUPPORTED_VERSIONS);
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(2); // 2 bytes length
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(TLS13_VERSION);
    bufoff +=2;


    *(short*)&(buffer[bufoff]) = htons(ET_KEY_SHARE);
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(2+(is_retry_request==0?2+tls_context.client_key_share.key_exchange.len:0)); // 2 for group, 2 for vector len
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(is_retry_request?tls_context.chosen_group:tls_context.client_key_share.group);
    bufoff +=2;
    
    if (!is_retry_request) {
        int keys_generated = generate_server_keys(&tls_context);
        if (keys_generated != 0) return keys_generated; // alerts
        *(short*)&(buffer[bufoff]) = htons(tls_context.server_key_share.key_exchange.len);
        bufoff +=2;
        
        memcpy(buffer+bufoff, tls_context.server_key_share.key_exchange.data, tls_context.server_key_share.key_exchange.len);
        bufoff += tls_context.server_key_share.key_exchange.len;
    }

    //if (is_retry_request && tls_context.chosen_signature_algo == 0) { // ET_SIGNATURE_ALGORITHMS is NOT one of the renegoatiable parameters
    //    *(short*)&(buffer[bufoff]) = htons(ET_SIGNATURE_ALGORITHMS);
    //    bufoff +=2;
    //
    //    *(short*)&(buffer[bufoff]) = htons(4); // 4 bytes complete length
    //    bufoff +=2;
    //    
    //    *(short*)&(buffer[bufoff]) = htons(2); // 2 bytes for the actual algo, tls uses the same extension format as from client hello
    //    bufoff +=2;
    //    
    //    *(short*)&(buffer[bufoff]) = htons(SS_ECDSA_SECP256R1_SHA256);
    //}

    switch (tls_context.chosen_cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            sha256_update(&tls_context.transcript_hash_ctx, buffer + sizeof(TLS_record_header), final_size-sizeof(TLS_record_header));
            break;
        case TLS_AES_256_GCM_SHA384:
            sha384_update(&tls_context.transcript_hash_ctx, buffer + sizeof(TLS_record_header), final_size-sizeof(TLS_record_header));
            print_hex_buf(buffer+sizeof(TLS_record_header), final_size - sizeof(TLS_record_header));
            break;
        default:
            fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
            return -AD_HANDSHAKE_FAILURE;
    }
    return final_size;
}

int handshake_tls(unsigned char * buffer, size_t record_end_offset, size_t len) {
    // see https://www.rfc-editor.org/rfc/rfc8446#section-4.4.1 for transcript hash reasoning 
    static char trying_helloretry = 0; // only case in which renegotiation is allowed, 1 = last message was hello retry request, 2 = already tried hello retry request
    int ret;

    TLS_handshake handshake = {0};

    size_t message_offset = record_end_offset; // for transcript hash - record layer is not a part of the transcript

    memcpy(&handshake, buffer + message_offset, sizeof(TLS_handshake));
    int handshake_len = htons(handshake.length);

    if (handshake_len > len-sizeof(TLS_handshake)) {
        fprintf(stderr, "Handshake length larger than recieved data!\n");
        return -AD_DECODE_ERROR;
    } else if (handshake_len < len-sizeof(TLS_handshake)){
        fprintf(stderr, "Warning: Handshake length smaller than recieved data!\n");
    }

    message_offset += sizeof(TLS_handshake);

    if ((tls_context.recv_message_counter == 1 || trying_helloretry == 1) && handshake.msg_type == HT_CLIENT_HELLO) { // start of tls
        if (trying_helloretry == 1) trying_helloretry = 2;

        struct ClientHello CH_packet = {0};
        memcpy(&CH_packet, buffer+message_offset, sizeof(CH_packet.legacy_version) + TLS_RANDOM_LEN); // 34 for legacy_version + random, rest are dynamic
        
        message_offset += sizeof(CH_packet.legacy_version) + TLS_RANDOM_LEN;


        if (CH_packet.legacy_version != htons(TLS12_COMPAT_VERSION)) { // doesn't need htons cuz big endian of 0x0303 is 0x0303 if you didn't know :3
            fprintf(stderr, "Invalid TLS client hello message (version %d))!\n", CH_packet.legacy_version);
            return -AD_ILLEGAL_PARAMETER; // shouldn't be sent by server, but is the best choice

        }

        fprintf(stderr, "Recieved TLS client hello!\n");
        parse_client_hello(buffer+message_offset, handshake_len - sizeof(TLS_handshake), &CH_packet);
        
        if ((ret = parse_extensions(CH_packet)) == -AD_HANDSHAKE_FAILURE) {
            if (tls_context.chosen_signature_algo == 0 || trying_helloretry == 2) goto CH_fail; // signature algorithms is nonrenegoatiable, cannot send hello retry request >1 times (see https://www.rfc-editor.org/rfc/rfc8446#section-4.1.4)
            fprintf(stderr, "Failed to find mutual parameters, trying helloretryrequest\n");
            trying_helloretry = 1;
        } else if (ret != 1) {
            CH_fail:
            fprintf(stderr, "Failed to parse TLS ClientHello extensions, returning alert %d\n", -ret);
            free_client_hello(CH_packet);
            return ret;
        }
        if (ret == 1) current_state = TS_SETTING_UP_SERVER_SIDE;
        switch (tls_context.chosen_cipher_suite) {
            case TLS_AES_128_GCM_SHA256:
                if (trying_helloretry != 2) sha256_init(&tls_context.transcript_hash_ctx);
                sha256_update(&tls_context.transcript_hash_ctx, buffer + record_end_offset, len);
                break;
            case TLS_AES_256_GCM_SHA384:
                if (trying_helloretry != 2) sha384_init(&tls_context.transcript_hash_ctx);
                sha384_update(&tls_context.transcript_hash_ctx, buffer + record_end_offset, len);
                break;
            default:
                fprintf(stderr, "Chosen unsupported cipher suite (how did we get here?)\n");
                return -AD_HANDSHAKE_FAILURE;
        }
        int out = construct_server_hello(buffer, MAX_REQUEST_SIZE, CH_packet, trying_helloretry == 1);
        if (trying_helloretry != 1) {
            generate_server_secrets(&tls_context);
            generate_traffic_keys(&tls_context, tls_context.client_hs_traffic_secret, tls_context.server_hs_traffic_secret);
        }
        free_client_hello(CH_packet);
        return out;
    } else if (handshake.msg_type == HT_CLIENT_HELLO) {
        fprintf(stderr, "Recieved renegotiation - invalid for TLS v1.3, closing connection!\n");
        return -AD_UNEXPECTED_MESSAGE;
    } else if (handshake.msg_type == HT_SERVER_HELLO) { // assuming the client sent a helloretryrequest
        fprintf(stderr, "Client sent helloretryrequest, not sure if that's even allowed (only mentioned in one sentence in 4.2.8), but not something we support anyway, closing connection\n");
        return -AD_UNEXPECTED_MESSAGE;
    } else {
        return -AD_DECODE_ERROR;
    }
    // blah blah blah current_state = TS_READY
    return -AD_UNEXPECTED_MESSAGE; // no way we get here
}

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
    *(TLS_handshake*)input_buf_wrapped = (TLS_handshake) {
        .msg_type = handshake_message_type,
        .length = htons(in_buf_len)
    };

    assert(input_buf_wrapped);
    memcpy(input_buf_wrapped + sizeof(TLS_handshake), input_buf, in_buf_len);
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

int decrypt_tls(unsigned char* buffer, size_t len) { // TODO: implement alerts, implement actually valid bounds checking

    if (len < sizeof(TLS_record_header)) {
        fprintf(stderr, "Recieved packet too short to be a valid TLS message (size was %lu)\n", len);
        return -AD_DECODE_ERROR;
    }

    size_t record_offset = 0;

    TLS_record_header record = {0};

    memcpy(&record, buffer, sizeof(TLS_record_header));
    record_offset += sizeof(TLS_record_header);

    get_wrapped:
    if (record.content_type == CT_INVALID || (record.content_type != CT_ALERT && record.content_type != CT_HANDSHAKE && record.content_type != CT_APPLICATION_DATA && record.content_type != CT_CHANGE_CIPHER_SPEC)) {
        fprintf(stderr, "Invalid TLS record content type!\n");
        return -AD_ILLEGAL_PARAMETER;
    }

    if (record.content_type == CT_CHANGE_CIPHER_SPEC) { // wrapped record (middlebox compatibility) (disguising tls 1.3 as tls 1.2)
        if (htons(record.length) == 1 && len == sizeof(TLS_record_header) + 1) return 0; // middlebox compatibility, basically wrapped CCS can be either at the start of a packet or its own packet (gnutls)
        if (record_offset + htons(record.length) + sizeof(TLS_record_header) >= len) goto trunc;
        record_offset += htons(record.length);
        memcpy(&record, buffer+record_offset, sizeof(TLS_record_header));
        record_offset += sizeof(TLS_record_header);
        goto get_wrapped;
    }

    record.legacy_record_version = htons(record.legacy_record_version);

    if (record.legacy_record_version != TLS11_COMPAT_VERSION && record.legacy_record_version != TLS12_COMPAT_VERSION) {
        fprintf(stderr, "Invalid TLS record version!\n");
        return -AD_PROTOCOL_VERSION; // shouldn't be sent by server, but is the best choice
    }
    
    record.length = htons(record.length);

    if (record.length > len-record_offset) {
        trunc:
        fprintf(stderr, "Invalid TLS record length/truncated!\n");
        return -AD_DECODE_ERROR;
    } else if (record.length < len-record_offset) {
        fprintf(stderr, "Warning: record length smaller than recieved data!\n");
    }

    switch (record.content_type) {
        case CT_ALERT:
            fprintf(stderr, "Recieved ALERT: level: 0x%02hhx, desc 0x%02hhx\n", *(buffer+sizeof(TLS_record_header)),*(buffer+sizeof(TLS_record_header)+1));
            return 0xFFFFFFFF;
            break;
        case CT_HANDSHAKE:
            if (len < sizeof(TLS_record_header)+sizeof(TLS_handshake)) return -AD_DECODE_ERROR;
            int out_len = handshake_tls(buffer, record_offset, record.length);
            return out_len; // negative = alert
        case CT_APPLICATION_DATA:
            // decrypt packet
            break;
    }

    
    return 0;
}

int construct_encrypted_extensions(unsigned char * buffer, size_t len) {
    static const unsigned char ee_packet[] = "\x00\x00";
    return encrypt_tls_packet(CT_HANDSHAKE, HT_ENCRYPTED_EXTENSIONS, buffer, len, ee_packet, sizeof(ee_packet) - 1);
}

int construct_certificate(unsigned char * buffer, size_t len) {
    size_t wrapped_cert_len = 
        sizeof(struct ServerCertificatesHeader) + 
        3 + // uint24_t for the certificate length
        ssl_cert_len +
        2 + // uint16_t for the extension length
        0 // we don't use any extensions
    ;
    unsigned char * wrapped_cert = calloc(wrapped_cert_len, 1);
    
    assert(wrapped_cert);

    *(struct ServerCertificatesHeader*) wrapped_cert = (struct ServerCertificatesHeader) {
        .certificate_request_context = 0,
        .cert_data_len = htons(wrapped_cert_len - sizeof(struct ServerCertificatesHeader))
    };
    *(unsigned short*)&wrapped_cert[sizeof(struct ServerCertificatesHeader)+1] = htons(ssl_cert_len); // uint24_t, need to skip the 1 byte
    memcpy(wrapped_cert + sizeof(struct ServerCertificatesHeader) + 3, ssl_cert, ssl_cert_len);

    // don't need to set uint16_t for extension length since they are 0 anyway

    int ret = encrypt_tls_packet(CT_HANDSHAKE, HT_CERTIFICATE, buffer, len, wrapped_cert, wrapped_cert_len);
    free(wrapped_cert);
    return ret;
}

void cleanup() {
    free(target_server_name);
    free(tls_context.client_key_share.key_exchange.data);
    free(tls_context.server_ecdhe_keys.private_key.data);
    free(tls_context.server_ecdhe_keys.public_key.data);
    free(tls_context.master_key.data);
    hkdf_free(tls_context.early_secret);
    hkdf_free(tls_context.handshake_secret);
    hkdf_free(tls_context.master_secret);
    free(tls_context.server_hs_traffic_secret.data);
    free(tls_context.client_hs_traffic_secret.data);
    free(tls_context.server_write_iv.data); 
    free(tls_context.client_write_iv.data);
    free(tls_context.server_write_key.data); 
    free(tls_context.client_write_key.data);
    free(tls_context.server_application_secret_0.data);
    free(tls_context.server_application_iv.data);
    free(tls_context.client_application_secret_0.data);
    free(tls_context.client_application_iv.data);
    free(ssl_cert);
}