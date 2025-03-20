#ifndef TLS_H
#define TLS_H

struct {
    unsigned int len;
    void * data;
} typedef Vector;


enum CipherSuites { // supported CipherSuites
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF, // no clue where to find this in the rfc but https://tls13.xargs.org/ had this
};
//const int supported_ciphers_len = 2;
//const unsigned short supported_ciphers[] = {TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384};

enum HandshakeTypes { // uchar
    HT_CLIENT_HELLO = 1,
    HT_SERVER_HELLO = 2,
    HT_NEW_SESSION_TICKET = 4,
    HT_END_OF_EARLY_DATA = 5,
    HT_ENCRYPTED_EXTENSIONS = 8,
    HT_CERTIFICATE = 11,
    HT_CERTIFICATE_REQUEST = 13,
    HT_CERTIFICATE_VERIFY = 15,
    HT_FINISHED = 20,
    HT_KEY_UPDATE = 24,
    HT_MESSAGE_HASH = 254,
};

enum ExtensionTypes { // ushort
    ET_SERVER_NAME = 0,                             /* RFC 6066 */
    ET_MAX_FRAGMENT_LENGTH = 1,                     /* RFC 6066 */
    ET_STATUS_REQUEST = 5,                          /* RFC 6066 */
    ET_SUPPORTED_GROUPS = 10,                       /* RFC 8422, 7919 */
    ET_SIGNATURE_ALGORITHMS = 13,                   /* RFC 8446 */
    ET_USE_SRTP = 14,                               /* RFC 5764 */
    ET_HEARTBEAT = 15,                              /* RFC 6520 */
    ET_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, /* RFC 7301 */
    ET_SIGNED_CERTIFICATE_TIMESTAMP = 18,           /* RFC 6962 */
    ET_CLIENT_CERTIFICATE_TYPE = 19,                /* RFC 7250 */
    ET_SERVER_CERTIFICATE_TYPE = 20,                /* RFC 7250 */
    ET_PADDING = 21,                                /* RFC 7685 */
    ET_PRE_SHARED_KEY = 41,                         /* RFC 8446 */
    ET_EARLY_DATA = 42,                             /* RFC 8446 */
    ET_SUPPORTED_VERSIONS = 43,                     /* RFC 8446 */
    ET_COOKIE = 44,                                 /* RFC 8446 */
    ET_PSK_KEY_EXCHANGE_MODES = 45,                 /* RFC 8446 */
    ET_CERTIFICATE_AUTHORITIES = 47,                /* RFC 8446 */
    ET_OID_FILTERS = 48,                            /* RFC 8446 */
    ET_POST_HANDSHAKE_AUTH = 49,                    /* RFC 8446 */
    ET_SIGNATURE_ALGORITHMS_CERT = 50,              /* RFC 8446 */
    ET_KEY_SHARE = 51,                              /* RFC 8446 */
};

extern const int supported_extensions_len;
extern const unsigned short supported_extensions[];

enum ContentType { // records, uchar
    CT_INVALID = 0,
    //CT_CHANGE_CIPHER_SPEC = 20, // TLS 1.2 compatibility
    CT_ALERT = 21,
    CT_HANDSHAKE = 22,
    CT_APPLICATION_DATA = 23,
};

struct {
    unsigned char content_type;
    unsigned short legacy_record_version; // always 0x0301
    unsigned short length;
    // unsigned char data[length]
} __attribute__((packed)) typedef TLS_plainttext_header;

struct {
    unsigned char msg_type;
    unsigned char length[3]; // uint24 ?????
}__attribute__((packed)) typedef TLS_handshake;

struct {
    unsigned short extension_type;
    Vector extension_data; //uint8, 0-65535
} typedef Extension;

struct ClientHello {
    unsigned short legacy_version; // = 0x0303
    unsigned char random[32];
    Vector legacy_session_id; // 0-32 bytes
    Vector cipher_suites; // uint8[2], 2-65534 bytes
    Vector legacy_compression_methods; // uint8 1-255, always 0
    Vector Extension; // Extension, 8-65535, minimally supported versions, for only tls1.3 that would be 43 for ext id with 3 bytes of len, 2 bytes of tls versions and 0x0304 (0x002b0003020304)
};


#endif