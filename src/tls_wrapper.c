#include <stddef.h>
#include <stdio.h>
#include <stdlib.h> // malloc, free
#include <assert.h>
#include <netinet/in.h> // sockaddr_in, htons
#include <sys/select.h>
#include <sys/socket.h> // recv, setsockopt
#include <time.h> // ctime

#include <string.h> // memset, strncmp

#include <errno.h>

#include <unistd.h> // close, access

#include "include/server.h"
#include "include/tls.h"
#include "include/tls_extensions.h"
#include "include/memstructs.h"

#define MIN(a,b) (a>b?b:a)
#define MAX(a,b) (a<b?b:a)


struct LinkedList {
    void * data;
    struct LinkedList * next;
} typedef LinkedList;

// targetting TLS v1.3, no compatibility mode based on https://www.rfc-editor.org/rfc/rfc8446

unsigned long message_counter = 0;

int decrypt_tls(unsigned char* buffer, size_t len);

void construct_alert(unsigned char alert_desc, unsigned char alert_level, unsigned char* buffer, size_t bufsiz) {
    assert(bufsiz >= sizeof(TLS_plainttext_header)+sizeof(struct Alert));
    memset(buffer, 0, bufsiz);
    ((TLS_plainttext_header*)buffer)->content_type = CT_ALERT;
    ((TLS_plainttext_header*)buffer)->legacy_record_version = htons(0x0301);
    ((TLS_plainttext_header*)buffer)->length = htons(2);
    ((struct Alert*)(buffer+sizeof(TLS_plainttext_header)))->alert_level = alert_level;
    ((struct Alert*)(buffer+sizeof(TLS_plainttext_header)))->alert_description = alert_desc;
}

void ssl_wrapper(int socket_fd) {
    int socks[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, socks) == 0);

    int inner_fd = socks[0];
    switch (fork()) {
        case 0:
            close(socks[0]);
            server(socks[1]);
            exit(EXIT_SUCCESS);
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

    unsigned char * buffer = malloc(MAX_REQUEST_SIZE);
    assert(buffer!=NULL);

    int recv_len = 0;

    int ret;

    while (select(MAX(socket_fd, inner_fd)+1, &set, NULL, NULL, NULL) != -1) {
        message_counter++;
        if (FD_ISSET(socket_fd, &set)) { // client sending a message
            FD_SET(inner_fd, &set);
            recv_len = recv(socket_fd, buffer, MAX_REQUEST_SIZE, 0);
            if ((ret = decrypt_tls(buffer, recv_len)) >= -MAX_REQUEST_SIZE) { // fully aware how r****ded this is
                //everything ok, decrypted buffer
                send(inner_fd, buffer, ret, 0);
            } else if (ret < -MAX_REQUEST_SIZE) {
                send(socket_fd, buffer, -(ret+MAX_REQUEST_SIZE), 0); // this message was internal to TLS (e.g. clienthello)
            } else {
                construct_alert(ret, AL_FATAL, buffer, MAX_REQUEST_SIZE);
                send(socket_fd, buffer, sizeof(TLS_plainttext_header)+sizeof(struct Alert), 0); // alert messages are always 7 bytes long
                exit(EXIT_FAILURE);
            } 
        } else { // server sending a message
            FD_SET(socket_fd, &set);
            recv_len = recv(inner_fd, buffer, MAX_REQUEST_SIZE, 0);
            //encrypt_tls(buffer, recv_len);
            send(socket_fd, buffer, recv_len, 0);
        }
    }
    perror("TLS wrapper select(): ");
    close(inner_fd);
    close(socket_fd);
    exit(errno == EINTR?EXIT_SUCCESS:EXIT_FAILURE);
}


void parse_client_hello(unsigned char * buffer, size_t len, struct ClientHello * CH) { // TODO: add human readable errors and valid alerts
    size_t message_offset = 0;
    
    CH->legacy_session_id.len = buffer[message_offset];
    CH->legacy_session_id.data = malloc(CH->legacy_session_id.len);
    assert(CH->legacy_session_id.data != NULL);
    assert(message_offset+CH->legacy_session_id.len+1<=len);
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

// Extensions
char * target_server_name = NULL;

struct KeyShareNode chosen_key_share = {0};
unsigned short chosen_signature_algo = 0;
unsigned short chosen_group = 0;
unsigned short chosen_cipher_suite = 0;

unsigned char random_crypto[32] = {0};

//Vector pkem = {0}; // pkem enum
//Vector pre_shared_key = {0};

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
                    return AD_ILLEGAL_PARAMETER;
                }
                fprintf(stderr, "Found SIGNATURE_ALGORITHMS extension\n");
                break;
            case ET_SUPPORTED_VERSIONS: // against RFC, but since we dont support anything other than 1.3, alert missing_extension
                if (parse_supported_versions_extension(&((unsigned char*)CH.extensions.data)[i], len) == 1) {
                    fprintf(stderr, "Bravo, the client indicated with a TLS 1.3 exclusive extension that it does not support TLS 1.3\n");
                    return AD_ILLEGAL_PARAMETER;
                }
                fprintf(stderr, "Found SUPPORTED_VERSIONS extension: TLS 1.3 supported\n");
                found_ver = 1;
                break;
            case ET_SERVER_NAME: // alert missing_extension
                if ((target_server_name = parse_server_name_extension(&((unsigned char*)CH.extensions.data)[i], len)) == NULL) {
                    fprintf(stderr, "Found SERVER_NAME ext, but values are invalid!\n");
                    return AD_ILLEGAL_PARAMETER;
                }
                fprintf(stderr, "Found SERVER_NAME extension: %s\n", target_server_name);
                break;
            case ET_SUPPORTED_GROUPS:
                supported_groups = parse_supported_groups_extension(&((unsigned char*)CH.extensions.data)[i], len);
                if (supported_groups.data == NULL) {
                    fprintf(stderr, "Found SUPPORTED_GROUPS extension, but values are invalid/missing!\n");
                    return AD_ILLEGAL_PARAMETER;
                }
                fprintf(stderr, "Found SUPPORTED_GROUPS extension\n");
                break;
            case ET_KEY_SHARE:
                key_shares = parse_key_share_groups_extension(&((unsigned char*)CH.extensions.data)[i], len);
                if (key_shares.node.key_exchange.data == NULL) {
                    fprintf(stderr, "Found KEY_SHARE extension, but values are invalid/missing!\n");
                    return AD_ILLEGAL_PARAMETER;
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
        return AD_MISSING_EXTENSION;
    }

    if (supported_groups.data == NULL) {
        return AD_MISSING_EXTENSION; // no clue if actually according to spec, nothing there, but SG seems important so idk
    }
    for (int i = 0; i < supported_groups.len/2; i++) {
        if (((short*)supported_groups.data)[i] == htons(NG_X25519)) {
            chosen_group = NG_X25519;
        }
    }
    if (chosen_group == 0) return AD_HANDSHAKE_FAILURE;
    free(supported_groups.data);

    for (int i = 0; i < signature_algorithms.len/2; i++) {
        if (((short*)signature_algorithms.data)[i] == htons(SS_ED25519)) {
            chosen_signature_algo = SS_ED25519;
        }
    }
    if (chosen_signature_algo == 0) return AD_HANDSHAKE_FAILURE;
    free(signature_algorithms.data);


    KeyShares *curr = &key_shares;
    do {
        if (curr->node.group == NG_X25519) {
            chosen_key_share = curr->node;
            break;
        }
    } while ((curr = curr->next) != NULL);
    if (chosen_key_share.group == 0) return AD_HANDSHAKE_FAILURE;

    curr = &key_shares; // cleanup key_shares
    KeyShares prev = key_shares;
    do {
        prev = *curr;
        if (curr != &key_shares) free(curr);
    } while ((curr = prev.next) != NULL);


    for (int i = 0; i < CH.cipher_suites.len/2; i++) {
        if (((short*)CH.cipher_suites.data)[i] == htons(TLS_AES_256_GCM_SHA384)) {
            chosen_cipher_suite = TLS_AES_256_GCM_SHA384;
        }
    }
    if (chosen_cipher_suite == 0) return AD_HANDSHAKE_FAILURE;

    return -1;
}

void free_client_hello(struct ClientHello CH) {
    free(CH.cipher_suites.data);
    free(CH.extensions.data);
    free(CH.legacy_compression_methods.data);
    free(CH.legacy_session_id.data);
}

int construct_server_hello(unsigned char * buffer, size_t len, struct ClientHello CH) {
    size_t extensions_len = 0;  // we dont't have any encrypted extensions
    //must respond to supported_versions, key_share
    extensions_len += 2+2+2; // 2 supported versions extension, 2 size, 2 supported version
    extensions_len += 2+2+2+2+chosen_key_share.key_exchange.len; // 2 key_share extension, 2 size, 2 chosen algo, 2 public key len

    size_t final_size = sizeof(TLS_plainttext_header) + sizeof(TLS_handshake) + 2 + 32 + 1 + CH.legacy_session_id.len + 2 + 1 + 2 + extensions_len;
        // 2 = version, 32 = server random, 1 = vector size for session_id, 2 = cipher suite, 1 = legacy compression, 2 = extensions len
    
    assert(final_size <= (1<<16)-1);
    assert(final_size <= len);

    buffer = buffer-sizeof(TLS_plainttext_header); // crazy ik, but too lazy, always works anyway
    memset(buffer, 0, len+sizeof(TLS_plainttext_header));
    
    size_t bufoff = sizeof(TLS_plainttext_header);
    ((TLS_plainttext_header*)buffer)->content_type = CT_HANDSHAKE;
    ((TLS_plainttext_header*)buffer)->legacy_record_version = htons(TLS12_COMPAT_VERSION);
    ((TLS_plainttext_header*)buffer)->length = htons(final_size-sizeof(TLS_plainttext_header));

    ((TLS_handshake*)(buffer+bufoff))->msg_type = HT_SERVER_HELLO;
    ((TLS_handshake*)(buffer+bufoff))->length[0] = 0;
    *(short*)&(((TLS_handshake*)(buffer+bufoff))->length[1]) = htons(final_size-sizeof(TLS_handshake)-sizeof(TLS_plainttext_header)); // length is uint24 so cheeky trick

    bufoff += sizeof(TLS_handshake);
    *(short*)(buffer+bufoff) = 0x0303;
    bufoff += 2;

    srandom(time(NULL));
    for (int i =0; i < 8; i++) { // get random for SH TODO: FIX!!! HAVE TO USE CSPRNG
        ((int*)(buffer+bufoff))[i] = random();
    }
    memcpy(random_crypto, buffer+bufoff, 32);
    bufoff += 32;

    buffer[bufoff] = CH.legacy_session_id.len;
    bufoff ++;

    memcpy(buffer+bufoff, CH.legacy_session_id.data, CH.legacy_session_id.len);
    buffer += CH.legacy_session_id.len;

    *(short*)(buffer+bufoff) = htons(TLS_AES_256_GCM_SHA384);
    buffer +=2;

    buffer[bufoff] = 0; // null compression
    bufoff ++;

    *(short*)&(buffer[bufoff]) = htons(extensions_len);
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(ET_SUPPORTED_VERSIONS);
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(0x0002);
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(TLS13_VERSION);
    bufoff +=2;


    *(short*)&(buffer[bufoff]) = htons(ET_KEY_SHARE);
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(2+2+chosen_key_share.key_exchange.len); // 2 for group, 2 for vector len
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(chosen_key_share.group);
    bufoff +=2;

    *(short*)&(buffer[bufoff]) = htons(chosen_key_share.key_exchange.len);
    bufoff +=2;

    memcpy(buffer+bufoff, chosen_key_share.key_exchange.data, chosen_key_share.key_exchange.len);
    return final_size;
}

int handshake_tls(unsigned char * buffer, size_t len) {
    int ret = -1;
    size_t message_offset = 0;
    TLS_handshake handshake = {0};
    memcpy(&handshake, buffer, sizeof(TLS_handshake));
    int handshake_len = (handshake.length[0] << 16) + (handshake.length[1] << 8) + handshake.length[2];

    if (handshake_len > len-sizeof(TLS_handshake)) {
        fprintf(stderr, "Handshake length larger than recieved data!\n");
        return AD_DECODE_ERROR;
    } else if (handshake_len < len-sizeof(TLS_handshake)){
        fprintf(stderr, "Warning: Handshake length smaller than recieved data!\n");
    }

    message_offset += sizeof(TLS_handshake);

    if (message_counter == 1 && handshake.msg_type == HT_CLIENT_HELLO) { // start of tls
        struct ClientHello CH_packet = {0};
        memcpy(&CH_packet, buffer+message_offset, 34); // 34 for legacy_version + random, rest are dynamic
        message_offset += 34;
        if (CH_packet.legacy_version != htons(TLS12_COMPAT_VERSION)) { // doesn't need htons cuz big endian of 0x0303 is 0x0303 if you didn't know :3
            fprintf(stderr, "Invalid TLS client hello message (version))!\n");
            return AD_ILLEGAL_PARAMETER; // shouldn't be sent by server, but is the best choice
        } else {
            fprintf(stderr, "Recieved TLS client hello!\n");
            parse_client_hello(buffer+message_offset, len-message_offset, &CH_packet);
            if ((ret = parse_extensions(CH_packet)) != -1) {
                fprintf(stderr, "Failed to parse TLS extensions!\n");
                free_client_hello(CH_packet);
                return ret;
            }
            free_client_hello(CH_packet);
            return -MAX_REQUEST_SIZE-construct_server_hello(buffer, len, CH_packet);
        }
    } else if (handshake.msg_type == HT_CLIENT_HELLO) {
        fprintf(stderr, "Recieved renegotiation - invalid for TLS v1.3, closing connection!\n");
        return AD_UNEXPECTED_MESSAGE;
    } else {
        construct_alert(AD_DECODE_ERROR, AL_FATAL, buffer, len);
        return AD_DECODE_ERROR;
    }
    return AD_UNEXPECTED_MESSAGE; // no way we get here
}

int decrypt_tls(unsigned char* buffer, size_t len) { // TODO: implement alerts

    if (len < sizeof(TLS_plainttext_header)) {
        return AD_DECODE_ERROR;
    }
    
    
    setvbuf(stdout, NULL, _IONBF, 0);
    write(STDOUT_FILENO, buffer, len);


    size_t record_offset = 0;

    TLS_plainttext_header record = {0};

    memcpy(&record, buffer, sizeof(TLS_plainttext_header));
    record_offset += sizeof(TLS_plainttext_header);

    if (record.content_type == CT_INVALID || (record.content_type != CT_ALERT && record.content_type != CT_HANDSHAKE && record.content_type != CT_APPLICATION_DATA)) {
        fprintf(stderr, "Invalid TLS record content type!\n");
        return AD_ILLEGAL_PARAMETER;
    }

    record.legacy_record_version = htons(record.legacy_record_version);

    if (record.legacy_record_version != 0x0301 && record.legacy_record_version != 0x0303) {
        fprintf(stderr, "Invalid TLS record version!\n");
        return AD_PROTOCOL_VERSION; // shouldn't be sent by server, but is the best choice
    }
    
    record.length = htons(record.length);

    if (record.length > len-sizeof(TLS_plainttext_header)) {
        fprintf(stderr, "Invalid TLS record length/truncated!\n");
        return AD_DECODE_ERROR;
    } else if (record.length < len-sizeof(TLS_plainttext_header)) {
        fprintf(stderr, "Warning: record length smaller than recieved data!\n");
    }

    switch (record.content_type) {
        case CT_ALERT:
            fprintf(stderr, "Recieved ALERT: level: 0x%02hhx, desc 0x%02hhx\n", *(buffer+sizeof(TLS_plainttext_header)),*(buffer+sizeof(TLS_plainttext_header)+1));
            exit(EXIT_FAILURE);
            break;
        case CT_HANDSHAKE:
            if (len < sizeof(TLS_plainttext_header)+sizeof(TLS_handshake)) return AD_DECODE_ERROR;
            return handshake_tls(buffer+record_offset, record.length);
        case CT_APPLICATION_DATA:
            break;
    }

    
    return 0;
}

void cleanup() {
    free(chosen_key_share.key_exchange.data);
    free(target_server_name);
}