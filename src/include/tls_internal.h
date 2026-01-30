#ifndef TLS_INTERNAL_H
#define TLS_INTERNAL_H

#define TLS13_VERSION 0x0304
#define TLS12_COMPAT_VERSION 0x0303
#define TLS11_COMPAT_VERSION 0x0301

#include "memstructs.h"

#define TLS_SERVER_HELLO_RETRY_REQUEST_MAGIC "\xCF\x21\xAD\x74\xE5\x9A\x61\x11\xBE\x1D\x8C\x02\x1E\x65\xB8\x91\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E\x07\x9E\x09\xE2\xC8\xA8\x33\x9C" // sha256 of "HelloRetryRequest", see rfc8446 page 32
//#define TLS_BACKCOMP_SERVER_CHANGE_CIPHER_SPEC "\x14\x03\x03\x00\x01\x01"
struct KeyShareNode {
    unsigned short group;
    Vector key_exchange;
};

struct KeyShares {
    struct KeyShareNode node;
    struct KeyShares * next;
} typedef KeyShares;

enum CipherSuites { // supported CipherSuites
    TLS_AES_128_GCM_SHA256 = 0x1301,        // supported
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

enum ExtensionTypes { // ushort, see rfc8446 page 37 for locations, wrong location = AD_ILLEGAL_PARAMETER
    //CH = client hello, SH = server hello, EE = encrypted extensions, CT = certificate, CR = certificate request, NST = new session ticket, HRR = hello retry request (from server)
    ET_SERVER_NAME = 0,                             /* CH, EE,      RFC 6066 */ // REQUIRED, implemeneted check
    ET_MAX_FRAGMENT_LENGTH = 1,                     /* CH, EE,      RFC 6066 */
    ET_STATUS_REQUEST = 5,                          /* CH, CR, CT,  RFC 6066 */
    ET_SUPPORTED_GROUPS = 10,                       /* CH, EE,      RFC 8422, 7919 */ // REQUIRED, implemented
    ET_SIGNATURE_ALGORITHMS = 13,                   /* CH, CR,      RFC 8446 */ // REQUIRED, implemented
    ET_USE_SRTP = 14,                               /* CH, EE,      RFC 5764 */
    ET_HEARTBEAT = 15,                              /* CH, EE,      RFC 6520 */
    ET_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, /* CH, EE,      RFC 7301 */
    ET_SIGNED_CERTIFICATE_TIMESTAMP = 18,           /* CH, CR, CT   RFC 6962 */
    ET_CLIENT_CERTIFICATE_TYPE = 19,                /* CH, EE,      RFC 7250 */
    ET_SERVER_CERTIFICATE_TYPE = 20,                /* CH, EE,      RFC 7250 */
    ET_PADDING = 21,                                /* CH,          RFC 7685 */
    ET_KEY_SHARE = 51,                              /* CH, SH, HRR, RFC 8446 */ // REQUIRED, implemented
    ET_PRE_SHARED_KEY = 41,                         /* CH, SH,      RFC 8446 */ // REQUIRED for PSK
    ET_PSK_KEY_EXCHANGE_MODES = 45,                 /* CH,          RFC 8446 */ // REQUIRED for PSK, implemented check, probably won't implement since it's not used normally
    ET_EARLY_DATA = 42,                             /* CH, EE, NST  RFC 8446 */
    ET_COOKIE = 44,                                 /* CH, HRR      RFC 8446 */ // REQUIRED, but wont implemenent since it's never used either way
    ET_SUPPORTED_VERSIONS = 43,                     /* CH, SH, HRR  RFC 8446 */ // REQUIRED, implemeneted
    ET_CERTIFICATE_AUTHORITIES = 47,                /* CH, CR       RFC 8446 */
    ET_OID_FILTERS = 48,                            /* CR,          RFC 8446 */
    ET_POST_HANDSHAKE_AUTH = 49,                    /* CH,          RFC 8446 */
    ET_SIGNATURE_ALGORITHMS_CERT = 50,              /* CH, CR       RFC 8446 */ // REQUIRED, implemented

    ET_SESSION_TICKET_IGNORE = 35,                  /* RFC 8446 */ // not required from server, but TLS clients include this extension usually
};

enum CertTypes {
    CERTTYPE_X509 = 0, // implicitly selected if nothing in certificate extensions and/or encrypted extensions
    CERTTYPE_RAW = 2, // would support, but most TLS clients don't send the extension and so it's not useful
    //CERTTYPE_1609DOT2 = 3
};

enum PskKeyExchangeModes { // uchar
    PKEM_KE = 0, // server MUST NOT return key_share
    PKEM_DHE_KE = 1,
};


/*
firefox supports the following: (everything except edwards)
0x0403 = SS_ECDSA_SECP256R1_SHA256
0x0503 = SS_ECDSA_SECP384R1_SHA384
0x0603 = SS_ECDSA_SECP521R1_SHA512
0x0804 = SS_RSA_PSS_RSAE_SHA256
0x0805 = SS_RSA_PSS_RSAE_SHA384
0x0806 = SS_RSA_PSS_RSAE_SHA512
0x0401 = SS_RSA_PKCS1_SHA256
0x0501 = SS_RSA_PKCS1_SHA384
0x0601 = SS_RSA_PKCS1_SHA512
0x0203 = SS_ECDSA_SHA1
0x0201 = SS_RSA_PKCS1_SHA1

chromium supports the following:
0x0403 = SS_ECDSA_SECP256R1_SHA256
0x0804 = SS_RSA_PSS_RSAE_SHA256
0x0401 = SS_RSA_PKCS1_SHA256
0x0503 = SS_ECDSA_SECP384R1_SHA384
0x0805 = SS_RSA_PSS_RSAE_SHA384
0x0501 = SS_RSA_PKCS1_SHA384
0x0806 = SS_RSA_PSS_RSAE_SHA512
0x0601 = SS_RSA_PKCS1_SHA512

curl supports the following: (literally everything and then some)
0x0905 = ?
0x0906 = ?
0x0904 = ?
0x0403 = SS_ECDSA_SECP256R1_SHA256
0x0503 = SS_ECDSA_SECP384R1_SHA384
0x0603 = SS_ECDSA_SECP521R1_SHA512
0x0807 = SS_ED25519
0x0808 = SS_ED448
0x081a = ?
0x081b = ?
0x081c = ?
0x0809 = SS_RSA_PSS_PSS_SHA256
0x080a = SS_RSA_PSS_PSS_SHA384
0x080b = SS_RSA_PSS_PSS_SHA512
0x0804 = SS_RSA_PSS_RSAE_SHA256
0x0805 = SS_RSA_PSS_RSAE_SHA384
0x0806 = SS_RSA_PSS_RSAE_SHA512
0x0401 = SS_RSA_PKCS1_SHA256
0x0501 = SS_RSA_PKCS1_SHA384
0x0601 = SS_RSA_PKCS1_SHA512
0x0303 = ?
0x0301 = ?
0x0302 = ?
0x0402 = ?
0x0502 = ?
0x0602 = ?

so I decided to instead of ed25519 (the original idea) to implement SS_ECDSA_SECPXXXR1_SHAXXX
*/
#define ESDSA_UNCOMPRESSED_POINT_FORMAT 0x04
enum SignatureSchemes {
    /* RSASSA-PKCS1-v1_5 algorithms */
    SS_RSA_PKCS1_SHA256 = 0x0401,
    SS_RSA_PKCS1_SHA384 = 0x0501,
    SS_RSA_PKCS1_SHA512 = 0x0601,

    /* ECDSA algorithms */
    // note: this is the uncompressed format indicated by 0x04 at the start of the public key, otherwise 0x0C
    //  client announces support for compressed formats using the ECPointFormatList extension, 
    //  but tls1.3 removed support for anything other than uncompressed format, so not implementing it
    SS_ECDSA_SECP256R1_SHA256 = 0x0403, // implemented
    SS_ECDSA_SECP384R1_SHA384 = 0x0503,
    SS_ECDSA_SECP521R1_SHA512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    SS_RSA_PSS_RSAE_SHA256 = 0x0804,
    SS_RSA_PSS_RSAE_SHA384 = 0x0805,
    SS_RSA_PSS_RSAE_SHA512 = 0x0806,

    /* EdDSA algorithms */
    SS_ED25519 = 0x0807,
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

/*
firefox supports the following:
0x11ec = X25519_ML-KEM-768 post quantum secured key exchange
0x001d = NG_X25519
0x0017 = NG_SECP256R1
0x0018 = NG_SECP384R1
0x0019 = NG_SECP512R1
0x0100 = NG_FFDHE2048
0x0101 = NG_FFDHE3072

chromium supports the following:
0xeaea = literally a random number to test that tls servers correctly ignore these fields
0x11ec = X25519_ML-KEM-768
0x001d = NG_X25519
0x0017 = NG_SECP256R1
0x0018 = NG_SECP384R1

curl supports the following:
0x11ec = X25519_ML-KEM-768
0x001d = NG_X25519
0x0017 = NG_SECP256R1
0x001e = NG_X448
0x0018 = NG_SECP384R1
0x0019 = NG_SECP512R1
0x0100 = NG_FFDHE2048
0x0101 = NG_FFDHE3072
*/

enum NamedGroups { // key share, ushort
    NG_SECP256R1 = 0x0017,// implemented uncompressed format
    NG_SECP384R1 = 0x0018,// will try to implement these
    NG_SECP521R1 = 0x0019,// will try to implement these
    NG_X25519 = 0x001d,
    NG_X448 = 0x001e,
    
    NG_FFDHE2048 = 0x0100,
    NG_FFDHE3072 = 0x0101,
    NG_FFDHE4096 = 0x0102,
    NG_FFDHE6144 = 0x0103,
    NG_FFDHE8192 = 0x0104,
    
};

enum ContentType { // records, uchar
    CT_INVALID = 0,
    CT_CHANGE_CIPHER_SPEC = 20, // TLS 1.2 compatibility
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

enum tls_state { // roughly what is written on page 120 of rfc8446
    TS_SETTING_UP_INTERACTIVE, // START
    TS_SETTING_UP_SERVER_SIDE, // RECVD_CH + NEGOTIATED
    TS_READY                   // CONNECTED
};

struct Alert {
    unsigned char alert_level;
    unsigned char alert_description;
} __attribute__((packed));

struct {
    unsigned char content_type;
    unsigned short legacy_record_version; // always 0x0301, unless wrapped in change cipher spec, in which case 0303
    unsigned short length;
    // unsigned char data[length]
} __attribute__((packed)) typedef TLS_record_header;

struct {
    unsigned char msg_type;
    unsigned char __pad; // length is technically uint24, but since the record layer itself has a uint16, this byte is always 0
    unsigned short length;
}__attribute__((packed)) typedef TLS_handshake;

struct {
    unsigned short extension_type;
    Vector extension_data; //uint8, 0-65535
} typedef Extension;

#define TLS_RANDOM_LEN 32
struct ClientHello {
    unsigned short legacy_version; // = 0x0303
    unsigned char random[TLS_RANDOM_LEN];
    Vector legacy_session_id; // 0-32 bytes
    Vector cipher_suites; // uint8[2], 2-65534 bytes
    Vector legacy_compression_methods; // uint8 1-255, always 0
    Vector extensions; // Extension, 8-65535, minimally supported versions, for only tls1.3 that would be 43 for ext id with 3 bytes of len, 2 bytes of tls versions and 0x0304 (0x002b0003020304)
} __attribute__((packed));

struct ServerHello {
    unsigned short legacy_version; // 0x0303
    unsigned char random[TLS_RANDOM_LEN];
    Vector legacy_session_id; // 0 - 32
    unsigned short cipher_suite; // better to work with than char[2]
    unsigned char legacy_compression_method; // 0
    Vector extensions;
};


/* the certificate packet looks like this
    certificate_req_context - 0 if server sending, what was in certificate request if client requesting
    CertificateEntry<0..2^24-1> certificate_list

    CertificateEntry:
    Vector<0..2^24-1> cert_data/ASN1_subjectPublicKeyInfo depending on certificate types, see CERTTYPE_X509 and CERTTYPE_RAW
    Vector<0..2^16-1> extensions
*/
struct ServerCertificatesHeader {
    unsigned char certificate_request_context;
    unsigned char __pad1;
    unsigned short cert_data_len; // the entire length of every single sent certificate
} __attribute__((packed));


#include "hkdf_tls.h"
#include "../crypto/include/sha2.h"
struct tls_context {
    sha2_ctx_t transcript_hash_ctx;

    uint64_t recv_message_counter, txd_message_counter;

    // context options
    unsigned short chosen_signature_algo;
    unsigned short chosen_group;
    unsigned short chosen_cipher_suite;

    // server's random data from server hello, don't think it's actually used anywhere
    unsigned char random_crypto[TLS_RANDOM_LEN];

    // DH keys
    struct KeyShareNode client_key_share, server_key_share;
    Keys server_ecdhe_keys;

    // traffic encryption keys, ivs, and secrets
    struct prk early_secret, handshake_secret, master_secret;
    Vector master_key, server_hs_traffic_secret, client_hs_traffic_secret;
    Vector server_write_key, server_write_iv, client_write_key, client_write_iv;
    Vector server_application_secret_0, server_application_iv, client_application_secret_0, client_application_iv;

    // certificates
    unsigned char * cert; // the der certificate that's sent across the network
    size_t cert_len;

    Keys cert_keys; // from private cert der
    enum NamedGroups cert_key_type;
};
extern struct tls_context tls_context;

#endif