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

#define MIN(a,b) (a>b?b:a)
#define MAX(a,b) (a<b?b:a)


struct LinkedList {
    void * data;
    struct LinkedList * next;
} typedef LinkedList;

// targetting TLS v1.3, no compatibility mode based on https://www.rfc-editor.org/rfc/rfc8446

unsigned long message_counter = 0;

int decrypt_tls(unsigned char* buffer, size_t len);

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

    while (select(MAX(socket_fd, inner_fd)+1, &set, NULL, NULL, NULL) != -1) {
        message_counter++;
        if (FD_ISSET(socket_fd, &set)) { // client sending a message
            FD_SET(inner_fd, &set);
            recv_len = recv(socket_fd, buffer, MAX_REQUEST_SIZE, 0);
            switch (decrypt_tls(buffer, recv_len)) {
                case 0:
                    break;
                case 1:
                    send(socket_fd, buffer, MAX_REQUEST_SIZE, 0); // this message was internal to TLS (e.g. clienthello)
                    break;
                case 2:
                    send(socket_fd, buffer, MAX_REQUEST_SIZE, 0); // critical error, will send alert, exit(EXIT_FAILURE)
                    exit(EXIT_FAILURE);
                    break;
            } 
            send(inner_fd, buffer, recv_len, 0);
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


void parse_client_hello(unsigned char * buffer, size_t len, struct ClientHello * CH) { // TODO: add human readable errors ig
    size_t message_offset = 0;
    
    CH->legacy_session_id.len = buffer[message_offset];
    CH->legacy_session_id.data = malloc(CH->legacy_session_id.len);
    assert(CH->legacy_session_id.data != NULL);
    assert(message_offset+CH->legacy_session_id.len+1<=len);
    memcpy(CH->legacy_session_id.data, buffer+message_offset+1, CH->legacy_session_id.len);
    message_offset += 1 + CH->legacy_session_id.len;

    CH->cipher_suites.len = htons(*(short*)&buffer[message_offset]);
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

    CH->Extension.len = htons(*(short*)&buffer[message_offset]);
    assert(CH->Extension.len >= 8);
    CH->Extension.data = malloc(CH->Extension.len);
    assert(CH->Extension.data != NULL);
    assert(message_offset+CH->Extension.len+2 <= len);
    memcpy(CH->Extension.data, buffer+message_offset+2, CH->Extension.len);
    message_offset += 2 + CH->Extension.len;
    
    fprintf(stderr, "CH: LSI: %hhu CS: %hu LCM: %hu EXT: %hu\n", CH->legacy_session_id.len, CH->cipher_suites.len, CH->legacy_compression_methods.len, CH->Extension.len);
}

char * target_server_name = NULL;

int parse_extensions(struct ClientHello CH) { // TODO: parse extentions .... :D
    unsigned short len, ext;
    for (int i = 0; i<CH.Extension.len;) {
        ext = htons(*(unsigned short*)&((unsigned char*)CH.Extension.data)[i]);
        i+=2;
        len = htons(*(unsigned short*)&((unsigned char*)CH.Extension.data)[i]);
        i+=2;
        if (len > CH.Extension.len) return 2;
        switch (ext) {
            case ET_PADDING:
                break;
            case ET_SUPPORTED_VERSIONS:
                if (parse_supported_versions_extension(&((unsigned char*)CH.Extension.data)[i], len) == 1) {
                    fprintf(stderr, "Bravo, the client indicated with a TLS 1.3 exclusive extension that it does not support TLS 1.3\n");
                    return 2;
                }
                fprintf(stderr, "TLS 1.3 in supported versions extension\n");
                break;
            case ET_SERVER_NAME:
                if ((target_server_name = parse_server_name_extension(&((unsigned char*)CH.Extension.data)[i], len)) == NULL) {
                    fprintf(stderr, "Found SERVER_NAME ext, but values are invalid!\n");
                    return 2;
                }
                fprintf(stderr, "Found extension server name: %s\n", target_server_name);
                break;
            default:
                fprintf(stderr, "Unknown extension id: %hx\n", ext);
        }
        i+=len;
    }
    return 0;
}

void free_client_hello(struct ClientHello CH) {
    free(CH.cipher_suites.data);
    free(CH.Extension.data);
    free(CH.legacy_compression_methods.data);
    free(CH.legacy_session_id.data);
}

int handshake_tls(unsigned char * buffer, size_t len) {
    size_t message_offset = 0;
    TLS_handshake handshake = {0};
    memcpy(&handshake, buffer, sizeof(TLS_handshake));
    int handshake_len = (handshake.length[0] << 16) + (handshake.length[1] << 8) + handshake.length[2];

    if (handshake_len > len-sizeof(TLS_handshake)) {
        fprintf(stderr, "Handshake length larger than recieved data!\n");
        return 2;
    } else if (handshake_len < len-sizeof(TLS_handshake)){
        fprintf(stderr, "Warning: Handshake length smaler than recieved data!\n");
    }

    message_offset += sizeof(TLS_handshake);

    if (message_counter == 1 && handshake.msg_type == HT_CLIENT_HELLO) { // start of tls
        struct ClientHello CH_packet = {0};
        memcpy(&CH_packet, buffer+message_offset, 34); // 34 for legacy_version + random, rest are dynamic
        message_offset += 34;
        if (CH_packet.legacy_version != 0x0303) { // doesn't need htons cuz big endian of 0x0303 if you didn't know :3
            fprintf(stderr, "Invalid TLS client hello message (version))!\n");
            return 2;
        } else {
            fprintf(stderr, "Recieved TLS client hello!\n");
            parse_client_hello(buffer+message_offset, len-message_offset, &CH_packet);
            if (parse_extensions(CH_packet) != 0) {
                fprintf(stderr, "Failed to parse TLS extensions!\n");
                free_client_hello(CH_packet);
                return 2;
            }
            free_client_hello(CH_packet);
            return 0;
        }
    } else if (handshake.msg_type == HT_CLIENT_HELLO) {
        fprintf(stderr, "Recieved renegotiation - invalid for TLS v1.3, closing connection!\n");
        return 2;
    }
    return 0;
}

int decrypt_tls(unsigned char* buffer, size_t len) { // TODO: implement alerts

    if (len < sizeof(TLS_plainttext_header)) {
        return 2;
    }
    
    
    setvbuf(stdout, NULL, _IONBF, 0);
    write(STDOUT_FILENO, buffer, len);


    size_t record_offset = 0;

    TLS_plainttext_header record = {0};

    memcpy(&record, buffer, sizeof(TLS_plainttext_header));
    record_offset += sizeof(TLS_plainttext_header);

    if (record.content_type == CT_INVALID || (record.content_type != CT_ALERT && record.content_type != CT_HANDSHAKE && record.content_type != CT_APPLICATION_DATA)) {
        fprintf(stderr, "Invalid TLS record content type!\n");
        return 2;
    }

    record.legacy_record_version = htons(record.legacy_record_version);

    if (record.legacy_record_version != 0x0301) {
        fprintf(stderr, "Invalid TLS record version!\n");
        return 2;
    }
    
    record.length = htons(record.length);

    if (record.length > len-sizeof(TLS_plainttext_header)) {
        fprintf(stderr, "Invalid TLS record length/truncated!\n");
        return 2;
    } else if (record.length < len-sizeof(TLS_plainttext_header)) {
        fprintf(stderr, "Warning: record length smaller than recieved data!\n");
    }

    switch (record.content_type) {
        case CT_ALERT:
            return 2;
        case CT_HANDSHAKE:
            if (len < sizeof(TLS_plainttext_header)+sizeof(TLS_handshake)) return 2;
            return handshake_tls(buffer+record_offset, record.length);
        case CT_APPLICATION_DATA:
            break;
    }

    
    return 1;
}