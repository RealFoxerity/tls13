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
#include "include/crypto/secp256.h"

#define MIN(a,b) (a>b?b:a)
#define MAX(a,b) (a<b?b:a)

// TODO: find time to rewrite most of htons to htobe16 for clarity

// targetting TLS v1.3, no compatibility mode based on https://www.rfc-editor.org/rfc/rfc8446

// Extensions
char * target_server_name = NULL;

struct KeyShareNode client_key_share = {0}; // includes our chosen algorithm
struct KeyShareNode server_key_share = {0}; // this and server_ecdhe_keys share the same pointer, free only one
Keys server_ecdhe_keys = {0}; // private & public keys, get type from client/server_key_share

Vector shared_master_key;

unsigned short chosen_signature_algo = 0;
unsigned short chosen_group = 0;
unsigned short chosen_cipher_suite = 0;

unsigned char random_crypto[32] = {0};

//Vector pkem = {0}; // pkem enum
//Vector pre_shared_key = {0};

unsigned char * tls_packet_buffer = NULL;

unsigned long message_counter = 0;

enum tls_state current_state = TS_SETTING_UP_INTERACTIVE;

void free_tls_metadata() {
    free(target_server_name);
    free(client_key_share.key_exchange.data);
    free(tls_packet_buffer);
}

int decrypt_tls(unsigned char* buffer, size_t len);

void construct_alert(unsigned char alert_desc, unsigned char alert_level, unsigned char* buffer, size_t bufsiz) {
    assert(bufsiz >= sizeof(TLS_plainttext_header)+sizeof(struct Alert));
    memset(buffer, 0, bufsiz);
    ((TLS_plainttext_header*)buffer)->content_type = CT_ALERT;
    ((TLS_plainttext_header*)buffer)->legacy_record_version = htons(TLS11_COMPAT_VERSION);
    ((TLS_plainttext_header*)buffer)->length = htons(2);
    ((struct Alert*)(buffer+sizeof(TLS_plainttext_header)))->alert_level = alert_level;
    ((struct Alert*)(buffer+sizeof(TLS_plainttext_header)))->alert_description = alert_desc;
}

void construct_encrypted_extensions(unsigned char * buffer, size_t len);

char ssl_wrapper(int socket_fd) {
    int socks[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, socks) == 0);

    int inner_fd = socks[0];
    switch (fork()) {
        case 0:
            close(socks[0]);
            server(socks[1]);
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
        message_counter++;
        if (FD_ISSET(socket_fd, &set)) { // client sending a message
            FD_SET(inner_fd, &set);
            recv_len = recv(socket_fd, tls_packet_buffer, MAX_REQUEST_SIZE, 0);
            
            if ((ret = decrypt_tls(tls_packet_buffer, recv_len)) == 0xFFFFFFFF) { // got alert
                free_tls_metadata();
                return EXIT_FAILURE;
            } else if (ret < 0) {
                construct_alert(-ret, AL_FATAL, tls_packet_buffer, MAX_REQUEST_SIZE);
                send(socket_fd, tls_packet_buffer, sizeof(TLS_plainttext_header)+sizeof(struct Alert), 0); // alert messages are always 7 bytes long
                free_tls_metadata();
                return (EXIT_FAILURE);
            }
            else {
                switch (current_state) {
                    case TS_READY:
                        send(inner_fd, tls_packet_buffer, ret, 0);
                        break;
                    case TS_SETTING_UP_INTERACTIVE: // during back and forth between client and server (client hello -> server hello...)
                        send(socket_fd, tls_packet_buffer, ret, 0);
                        break;
                    case TS_SETTING_UP_SERVER_SIDE: // sending the actual server hello, change cipher spec, wrapped records, encrypted extensions
                        send(socket_fd, tls_packet_buffer, ret, 0);
                    default:
                        break;
                }
            }
        
        } else { // server sending a message
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
            chosen_group = NG_SECP256R1;
        }
    }
    free(supported_groups.data);

    for (int i = 0; i < signature_algorithms.len/2; i++) {
        if (((short*)signature_algorithms.data)[i] == htons(SS_ECDSA_SECP256R1_SHA256)) {
            chosen_signature_algo = SS_ECDSA_SECP256R1_SHA256;
        }
    }
    free(signature_algorithms.data);

    KeyShares *curr = &key_shares;
    printf("Client provided supported key shares:\n");
    do {
        printf("%04hx\n", curr->node.group);
        if (curr->node.group == NG_SECP256R1) {
            client_key_share = curr->node;
            //break;
        }
    } while ((curr = curr->next) != NULL);

    curr = &key_shares; // cleanup key_shares
    KeyShares prev = {0};
    prev = key_shares;
    do {
        prev = *curr;
        if (curr->node.key_exchange.data != client_key_share.key_exchange.data) // for some reason can't do curr->node != chosen_key_share
            free(curr->node.key_exchange.data);
        if (curr != &key_shares) {
            free(curr);
        };
    } while ((curr = prev.next) != NULL);

    for (int i = 0; i < CH.cipher_suites.len/2; i++) {
        if (((short*)CH.cipher_suites.data)[i] == htons(TLS_AES_256_GCM_SHA384)) {
            chosen_cipher_suite = TLS_AES_256_GCM_SHA384;
        }
    }

    if (chosen_signature_algo == 0) {
        printf("No mutually supported signature algorithms\n");
        return -AD_HANDSHAKE_FAILURE;
    }

    if (client_key_share.group == 0) {
        printf("No mutually supported key share algorithms\n");
        return -AD_HANDSHAKE_FAILURE;
    }

    if (chosen_group == 0) {
        printf("No mutually supported named groups\n");   
        return -AD_HANDSHAKE_FAILURE;
    }

    if (chosen_cipher_suite == 0) {
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

static int generate_server_keys() {
    if (client_key_share.group != NG_SECP256R1) {
        fprintf(stderr, "Unsupported key share group!\n");
        return -AD_HANDSHAKE_FAILURE;
    }

    struct secp_key keys = secp256_gen_public_key();
    assert(keys.public_key);
    assert(keys.private_key);

    server_ecdhe_keys.private_key.len = SECP256_PRIVKEY_SIZE;
    server_ecdhe_keys.private_key.data = keys.private_key;

    server_ecdhe_keys.public_key.len = SECP256_PUBKEY_SIZE;
    server_ecdhe_keys.public_key.data = keys.public_key;

    server_key_share.group = NG_SECP256R1;
    server_key_share.key_exchange.len = SECP256_PUBKEY_SIZE;
    server_key_share.key_exchange.data = keys.public_key;

    shared_master_key.len = SECP256_PRIVKEY_SIZE;
    shared_master_key.data = secp256_get_shared_key(server_ecdhe_keys.private_key.data, client_key_share.key_exchange.data);
    assert(shared_master_key.data);

    return 0;
}

int construct_server_hello(unsigned char * buffer, size_t len, struct ClientHello CH, char is_retry_request) {
    size_t extensions_len = 0;  // we dont't have any encrypted extensions
    //must respond to supported_versions, key_share
    extensions_len += 2+2+2; // 2 supported versions extension id, 2 size, 2 supported version
    extensions_len += 2+2+2+(is_retry_request==0?(2+client_key_share.key_exchange.len):0); // 2 key_share extension id, 2 size, 2 chosen algo, 2 public key len, public key
        
    //extensions_len += ((is_retry_request && chosen_signature_algo == 0)?(2+2+2+2):0); // not supported, look below - 2 signature_algo id, 2 size, 2 preferred algo vec size, 2 preferred algo

    size_t final_size = 
    sizeof(TLS_plainttext_header) +
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

    *(TLS_plainttext_header *)buffer = (TLS_plainttext_header) {
        .content_type = CT_HANDSHAKE,
        .legacy_record_version = htons(TLS12_COMPAT_VERSION),
        .length = htons(final_size-sizeof(TLS_plainttext_header))
    };

    size_t bufoff = sizeof(TLS_plainttext_header);

    ((TLS_handshake*)(buffer+bufoff))->msg_type = HT_SERVER_HELLO;
    ((TLS_handshake*)(buffer+bufoff))->length[0] = 0;
    *(short*)&(((TLS_handshake*)(buffer+bufoff))->length[1]) = htons(final_size-sizeof(TLS_handshake)-sizeof(TLS_plainttext_header)); // length is uint24 so cheeky trick

    bufoff += sizeof(TLS_handshake);
    *(short*)(buffer+bufoff) = TLS12_COMPAT_VERSION;
    bufoff += 2;

    if (!is_retry_request) {
        srandom(time(NULL));
        for (int i =0; i < 8; i++) { // get random for server random field TODO: FIX!!! HAVE TO USE CSPRNG
            ((int*)(buffer+bufoff))[i] = random();
        }
        memcpy(random_crypto, buffer+bufoff, TLS_RANDOM_LEN);
    } else {
        memcpy(buffer+bufoff, TLS_SERVER_HELLO_RETRY_REQUEST_MAGIC, TLS_RANDOM_LEN);
    }
    bufoff += TLS_RANDOM_LEN;

    buffer[bufoff] = CH.legacy_session_id.len;
    bufoff ++;

    memcpy(buffer+bufoff, CH.legacy_session_id.data, CH.legacy_session_id.len);
    buffer += CH.legacy_session_id.len;

    assert(is_retry_request || (chosen_cipher_suite != 0));
    *(short*)(buffer+bufoff) = htons(chosen_cipher_suite == 0?TLS_AES_256_GCM_SHA384:chosen_cipher_suite); // TODO: implement more
    buffer +=2;

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

    *(short*)&(buffer[bufoff]) = htons(2+(is_retry_request==0?2+client_key_share.key_exchange.len:0)); // 2 for group, 2 for vector len
    bufoff +=2;
    
    *(short*)&(buffer[bufoff]) = htons(is_retry_request?NG_SECP256R1:client_key_share.group);
    bufoff +=2;
    
    if (!is_retry_request) {
        int keys_generated = generate_server_keys();
        if (keys_generated != 0) return keys_generated; // alerts
        *(short*)&(buffer[bufoff]) = htons(server_key_share.key_exchange.len);
        bufoff +=2;
        
        memcpy(buffer+bufoff, server_key_share.key_exchange.data, server_key_share.key_exchange.len);
        bufoff += server_key_share.key_exchange.len;
    }

    //if (is_retry_request && chosen_signature_algo == 0) { // ET_SIGNATURE_ALGORITHMS is NOT one of the renegoatiable parameters
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
    return final_size;
}

int handshake_tls(unsigned char * buffer, size_t message_offset, size_t len) {
    static char trying_helloretry = 0; // only case in which renegotiation is allowed
    int ret;

    TLS_handshake handshake = {0};
    memcpy(&handshake, buffer + message_offset, sizeof(TLS_handshake));
    int handshake_len = (handshake.length[0] << 16) + (handshake.length[1] << 8) + handshake.length[2];

    if (handshake_len > len-sizeof(TLS_handshake)) {
        fprintf(stderr, "Handshake length larger than recieved data!\n");
        return -AD_DECODE_ERROR;
    } else if (handshake_len < len-sizeof(TLS_handshake)){
        fprintf(stderr, "Warning: Handshake length smaller than recieved data!\n");
    }

    message_offset += sizeof(TLS_handshake);

    if ((message_counter == 1 || trying_helloretry) && handshake.msg_type == HT_CLIENT_HELLO) { // start of tls
        if (trying_helloretry) trying_helloretry = 0;

        struct ClientHello CH_packet = {0};
        memcpy(&CH_packet, buffer+message_offset, sizeof(CH_packet.legacy_version) + TLS_RANDOM_LEN); // 34 for legacy_version + random, rest are dynamic
        
        message_offset += sizeof(CH_packet.legacy_version) + TLS_RANDOM_LEN;


        if (CH_packet.legacy_version != htons(TLS12_COMPAT_VERSION)) { // doesn't need htons cuz big endian of 0x0303 is 0x0303 if you didn't know :3
            fprintf(stderr, "Invalid TLS client hello message (version %d))!\n", CH_packet.legacy_version);
            return -AD_ILLEGAL_PARAMETER; // shouldn't be sent by server, but is the best choice

        } else {
            fprintf(stderr, "Recieved TLS client hello!\n");
            parse_client_hello(buffer+message_offset, handshake_len - sizeof(TLS_handshake), &CH_packet);
            
            if ((ret = parse_extensions(CH_packet)) == -AD_HANDSHAKE_FAILURE) {
                if (chosen_signature_algo == 0) goto CH_fail; // signature algorithms is nonrenegoatiable
                fprintf(stderr, "Failed to find mutual parameters, trying helloretryrequest\n");
                trying_helloretry = 1;
            } else if (ret != 1) {
                CH_fail:
                fprintf(stderr, "Failed to parse TLS ClientHello extensions, returning alert %d\n", -ret);
                free_client_hello(CH_packet);
                return ret;
            }
            int out = construct_server_hello(buffer, len, CH_packet, (ret != 1)?1:0);
            if (ret == 1) current_state = TS_SETTING_UP_SERVER_SIDE;
            free_client_hello(CH_packet);
            return out;
        }
    } else if (handshake.msg_type == HT_CLIENT_HELLO) {
        fprintf(stderr, "Recieved renegotiation - invalid for TLS v1.3, closing connection!\n");
        return -AD_UNEXPECTED_MESSAGE;
    } else {
        return -AD_DECODE_ERROR;
    }
    // blah blah blah current_state = TS_READY
    return -AD_UNEXPECTED_MESSAGE; // no way we get here
}


int decrypt_tls(unsigned char* buffer, size_t len) { // TODO: implement alerts, implement actually valid bounds checking

    if (len < sizeof(TLS_plainttext_header)) {
        return -AD_DECODE_ERROR;
    }
    
    
    // debug to see the actual packet
    setvbuf(stdout, NULL, _IONBF, 0);
    write(STDOUT_FILENO, buffer, len);


    size_t record_offset = 0;

    TLS_plainttext_header record = {0};

    memcpy(&record, buffer, sizeof(TLS_plainttext_header));
    record_offset += sizeof(TLS_plainttext_header);

    get_wrapped:
    if (record.content_type == CT_INVALID || (record.content_type != CT_ALERT && record.content_type != CT_HANDSHAKE && record.content_type != CT_APPLICATION_DATA && record.content_type != CT_CHANGE_CIPHER_SPEC)) {
        fprintf(stderr, "Invalid TLS record content type!\n");
        return -AD_ILLEGAL_PARAMETER;
    }

    if (record.content_type == CT_CHANGE_CIPHER_SPEC) { // wrapped record (middlebox compatibility) (disguising tls 1.3 as tls 1.2)
        if (record_offset + htons(record.length) + sizeof(TLS_plainttext_header) >= len) goto trunc;
        record_offset += htons(record.length);
        memcpy(&record, buffer+record_offset, sizeof(TLS_plainttext_header));
        record_offset += sizeof(TLS_plainttext_header);
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
            fprintf(stderr, "Recieved ALERT: level: 0x%02hhx, desc 0x%02hhx\n", *(buffer+sizeof(TLS_plainttext_header)),*(buffer+sizeof(TLS_plainttext_header)+1));
            return 0xFFFFFFFF;
            break;
        case CT_HANDSHAKE:
            if (len < sizeof(TLS_plainttext_header)+sizeof(TLS_handshake)) return -AD_DECODE_ERROR;
            int out_len = handshake_tls(buffer, record_offset, record.length);
            return out_len; // negative = alert
        case CT_APPLICATION_DATA:
            break;
    }

    
    return 0;
}

void construct_encrypted_extensions(unsigned char * buffer, size_t len) {


}

void cleanup() {
    free(client_key_share.key_exchange.data);
    free(target_server_name);
    free(server_ecdhe_keys.private_key.data);
    free(server_ecdhe_keys.public_key.data);
    free(shared_master_key.data);
}