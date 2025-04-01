#ifndef TLS_H
#define TLS_H

struct {
    unsigned int len;
    void * data;
} typedef Vector;

struct KeyShareNode {
    unsigned short group;
    Vector key_exchange;
};

struct KeyShares {
    struct KeyShareNode node;
    struct KeyShares * next;
} typedef KeyShares;

enum CipherSuites { // supported CipherSuites
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,        // supported
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF, // no clue where to find this in the rfc but https://tls13.xargs.org/ had this
};

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
    ET_SERVER_NAME = 0,                             /* RFC 6066 */ // REQUIRED, implemeneted check
    ET_MAX_FRAGMENT_LENGTH = 1,                     /* RFC 6066 */
    ET_STATUS_REQUEST = 5,                          /* RFC 6066 */
    ET_SUPPORTED_GROUPS = 10,                       /* RFC 8422, 7919 */ // REQUIRED, implemented check
    ET_SIGNATURE_ALGORITHMS = 13,                   /* RFC 8446 */ // REQUIRED, implemented check
    ET_USE_SRTP = 14,                               /* RFC 5764 */
    ET_HEARTBEAT = 15,                              /* RFC 6520 */
    ET_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, /* RFC 7301 */
    ET_SIGNED_CERTIFICATE_TIMESTAMP = 18,           /* RFC 6962 */
    ET_CLIENT_CERTIFICATE_TYPE = 19,                /* RFC 7250 */
    ET_SERVER_CERTIFICATE_TYPE = 20,                /* RFC 7250 */
    ET_PADDING = 21,                                /* RFC 7685 */
    ET_PRE_SHARED_KEY = 41,                         /* RFC 8446 */ // REQUIRED for PSK
    ET_EARLY_DATA = 42,                             /* RFC 8446 */
    ET_SUPPORTED_VERSIONS = 43,                     /* RFC 8446 */ // REQUIRED, implemeneted check
    ET_COOKIE = 44,                                 /* RFC 8446 */ // REQUIRED, but wont implemenent since it's never used either way
    ET_PSK_KEY_EXCHANGE_MODES = 45,                 /* RFC 8446 */ // REQUIRED for PSK, implemented check, probably not implement since it's not used normally
    ET_CERTIFICATE_AUTHORITIES = 47,                /* RFC 8446 */
    ET_OID_FILTERS = 48,                            /* RFC 8446 */
    ET_POST_HANDSHAKE_AUTH = 49,                    /* RFC 8446 */
    ET_SIGNATURE_ALGORITHMS_CERT = 50,              /* RFC 8446 */ // REQUIRED, implemented check
    ET_KEY_SHARE = 51,                              /* RFC 8446 */ // REQUIRED, implemented check
    ET_SESSION_TICKET_IGNORE = 35,                  /* RFC 8446 */ // not required from server, but TLS clients include this extension usually
};

enum PskKeyExchangeModes { // uchar
    PKEM_KE = 0, // server MUST NOT return key_share
    PKEM_DHE_KE = 1,
};

enum SignatureSchemes {
    /* RSASSA-PKCS1-v1_5 algorithms */
    SS_RSA_PKCS1_SHA256 = 0x0401,
    SS_RSA_PKCS1_SHA384 = 0x0501,
    SS_RSA_PKCS1_SHA512 = 0x0601,

    /* ECDSA algorithms */
    SS_ECDSA_SECP256R1_SHA256 = 0x0403,
    SS_ECDSA_SECP384R1_SHA384 = 0x0503,
    SS_ECDSA_SECP521R1_SHA512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    SS_RSA_PSS_RSAE_SHA256 = 0x0804,
    SS_RSA_PSS_RSAE_SHA384 = 0x0805,
    SS_RSA_PSS_RSAE_SHA512 = 0x0806,

    /* EdDSA algorithms */
    SS_ED25519 = 0x0807,     // supported
    SS_ED448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    SS_RSA_PSS_PSS_SHA256 = 0x0809,
    SS_RSA_PSS_PSS_SHA384 = 0x080a,
    SS_RSA_PSS_PSS_SHA512 = 0x080b,

    /* Legacy algorithms */
    SS_RSA_PKCS1_SHA1 = 0x0201,
    SS_ECDSA_SHA1 = 0x0203,

    /* Reserved Code Points */
    //private_use(0xFE00..0xFFFF),
    //(0xFFFF)
};

enum NamedGroups { // key share, ushort
    NG_SECP256R1 = 0x0017,
    NG_SECP384R1 = 0x0018,
    NG_SECP512R1 = 0x0019,
    NG_X25519 = 0x001d,   // only one going to be implemented
    NG_X448 = 0x001e,
    
    NG_FFDHE2048 = 0x0100,
    NG_FFDHE3072 = 0x0101,
    NG_FFDHE4096 = 0x0102,
    NG_FFDHE6144 = 0x0103,
    NG_FFDHE8192 = 0x0104,
    
};

enum ContentType { // records, uchar
    CT_INVALID = 0,
    //CT_CHANGE_CIPHER_SPEC = 20, // TLS 1.2 compatibility
    CT_ALERT = 21,
    CT_HANDSHAKE = 22,
    CT_APPLICATION_DATA = 23,
};

enum AlertLevel { // uchar
    AL_WARNING = 1,
    AL_FATAL = 2,
};

enum AlertDescription { // uchar
    AD_CLOSE_NOTIFY = 0,  // warn
    AD_UNEXPECTED_MESSAGE =10,  // fatal
    AD_BAD_RECORD_MAC = 20,  // fatal
    AD_RECORD_OVERFLOW = 22,  // fatal
    AD_HANDSHAKE_FAILURE = 40,  // fatal
    AD_BAD_CERTIFICATE = 42,  // fatal
    AD_UNSUPPORTED_CERTIFICATE = 43,  // fatal
    AD_CERTIFICATE_REVOKED = 44,  // fatal
    AD_CERTIFICATE_EXPIRED = 45,  // fatal
    AD_CERTIFICATE_UNKNOWN = 46,  // fatal
    AD_ILLEGAL_PARAMETER = 47,  // fatal
    AD_UNKNOWN_CA = 48,  // fatal
    AD_ACCESS_DENIED = 49,  // fatal
    AD_DECODE_ERROR = 50,  // fatal
    AD_DECRYPT_ERROR = 51,  // fatal
    AD_PROTOCOL_VERSION = 70,  // fatal
    AD_INSUFFICIENT_SECURITY = 71,  // fatal
    AD_INTERNAL_ERROR = 80,  // fatal
    AD_INAPPROPRIATE_FALLBACK = 86,  // fatal
    AD_USER_CANCELED = 90,  // warn
    AD_MISSING_EXTENSION = 109,  // fatal
    AD_UNSUPPORTED_EXTENSION = 110,  // fatal
    AD_UNRECOGNIZED_NAME = 112,  // fatal
    AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113,  // fatal
    AD_UNKNOWN_PSK_IDENTITY = 115,  // fatal
    AD_CERTIFICATE_REQUIRED = 116,  // fatal
    AD_NO_APPLICATION_PROTOCOL = 120,  // fatal
};

struct Alert {
    unsigned char alert_level;
    unsigned char alert_description;
} __attribute__((packed));

struct {
    unsigned char content_type;
    unsigned short legacy_record_version; // always 0x0301
    unsigned short length;
    // unsigned char data[length]
} __attribute__((packed)) typedef TLS_plainttext_header;

struct {
    unsigned char msg_type;
    unsigned char length[3]; // uint24 ????? HOW EVEN IF TLS_PLAINTEXT_HEADER HAS UNSIGNED SHORT (prolly pad but still)
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
    Vector extensions; // Extension, 8-65535, minimally supported versions, for only tls1.3 that would be 43 for ext id with 3 bytes of len, 2 bytes of tls versions and 0x0304 (0x002b0003020304)
};

struct ServerHello {
    unsigned short legacy_version; // 0x0303
    unsigned char random[32];
    Vector legacy_session_id; // 0 - 32
    unsigned short cipher_suite; // better to work with than char[2]
    unsigned char legacy_compression_method; // 0
    Vector extensions;
};

#endif