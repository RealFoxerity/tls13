#include "include/x.509.h"

#include "crypto/include/secp256.h"
#include "include/memstructs.h"
#include "include/x9.62.h"
#include "include/asn.1.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SECP256R1_OID "\x2a\x86\x48\xce\x3d\x03\x01\x07" // see note in x9.62.h
#define X963_KEY_TYPE_ECPUBKEY "\x2a\x86\x48\xce\x3d\x02\x01"
#define X962_EC_KEY_OID "\x2a\x86\x48\xce\x3d\x03\x01\xFF" // FF just as a placeholder to pad length
/*
    rfc5915 describes the private key structure, which is the .der private key file
    ECPrivateKey ::= SEQUENCE {
        version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        privateKey     OCTET STRING,
        parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        publicKey  [1] BIT STRING OPTIONAL
    }
    in our case
    1
    private key
    2a:86:48:ce:3d:03:01:07
    public key
*/


/*
    according to rfc5280, X.509 certificates are structured as follows:
    Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

    tbsCertificate is basically the identifying information including the public key and curve details, we need this
    signatureAlgorithm is the type of signature this certificate itself was signed with
    signatureValue is the signature

    tbsCertificate field is then structured like this:
    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,        <--- we care about this one
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                            -- If present, version MUST be v2 or v3
                            subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                            -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                            -- If present, version MUST be v3
        }
    version being Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

    subjectPublicKeyInfo, which is what we're after is then structured like this:
    SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }
    
    AlgorithmIdentifier then finally being structured:
    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }
    easy, right?
*/

static inline char check_asn1_node(struct asn1_node node, char constructed, enum asn1_tag_class tag_class, enum asn1_tags tag) {
    if (node.constructed != constructed) return 0;
    if (node.tag != tag) return 0;
    if (node.tag_class != tag_class) return 0;

    return 1;
}

static inline char x509_basic_is_cert_ok(const unsigned char * pub_cert, size_t pub_len) {
    assert(pub_cert);

    struct asn1_node certificate = asn1_get_next(pub_cert, pub_len);
    if (!certificate.data) return 0;
    if (certificate.header_len + certificate.len != pub_len) return 0;
    if (!check_asn1_node(certificate, 1, ASN1_TAG_UNIVERSAL, ASN1_SEQUENCE)) return 0;

    struct asn1_node tbsCertificate = asn1_get_next(certificate.data, certificate.len);
    if (!tbsCertificate.data) return 0;
    if (!check_asn1_node(tbsCertificate, 1, ASN1_TAG_UNIVERSAL, ASN1_SEQUENCE)) return 0;

    struct asn1_node signatureAlgorithm = asn1_get_next(tbsCertificate.data + tbsCertificate.len, certificate.len - tbsCertificate.header_len - tbsCertificate.len);
    if (!signatureAlgorithm.data) return 0;
    if (!check_asn1_node(signatureAlgorithm, 1, ASN1_TAG_UNIVERSAL, ASN1_SEQUENCE)) return 0;

    struct asn1_node signatureValue = asn1_get_next(signatureAlgorithm.data + signatureAlgorithm.len, certificate.len - tbsCertificate.header_len - tbsCertificate.len - signatureAlgorithm.header_len - signatureAlgorithm.len);
    if (!signatureValue.data) return 0;
    if (!check_asn1_node(signatureValue, 0, ASN1_TAG_UNIVERSAL, ASN1_BIT_STRING)) return 0;

    if (tbsCertificate.header_len + tbsCertificate.len +
        signatureAlgorithm.header_len + signatureAlgorithm.len +
        signatureValue.header_len + signatureValue.len != certificate.len) return 0;
    return 1;
}

static inline enum x509_cert_status x509_check_cert(const unsigned char * pub_cert, size_t pub_len, Vector curve, Vector public_key) {
    assert(pub_cert);
    if (!x509_basic_is_cert_ok(pub_cert, pub_len)) return X509_CERT_NOT_PARSABLE;
    struct asn1_node certificate = asn1_get_next(pub_cert, pub_len);
    struct asn1_node tbsCertificate = asn1_get_next(certificate.data, certificate.len);

    size_t tbs_offset = 0; // how far into tbsCertificate we are
    for (int i = 0; i < 6; i++) { // skip over to subjectPublicKeyInfo
        struct asn1_node temp = asn1_get_next(tbsCertificate.data + tbs_offset, tbsCertificate.len - tbs_offset);
        if (!temp.data) return X509_CERT_NOT_PARSABLE;
        tbs_offset += temp.header_len + temp.len;
    }

    struct asn1_node subjectPublicKeyInfo = asn1_get_next(tbsCertificate.data + tbs_offset, tbsCertificate.len - tbs_offset);
    if (!subjectPublicKeyInfo.data) return X509_CERT_NOT_PARSABLE;
    if (!check_asn1_node(subjectPublicKeyInfo, 1, ASN1_TAG_UNIVERSAL, ASN1_SEQUENCE)) return X509_CERT_NOT_PARSABLE;

    /*
    SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }
    
    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }    <--- TECHNICALLY optional, but for EC at least always populated with curve oid, TODO: rewrite?
    */

    struct asn1_node algorithm = asn1_get_next(subjectPublicKeyInfo.data, subjectPublicKeyInfo.len);
    if (!algorithm.data) return X509_CERT_NOT_PARSABLE;
    if (!check_asn1_node(algorithm, 1, ASN1_TAG_UNIVERSAL, ASN1_SEQUENCE)) return X509_CERT_NOT_PARSABLE;

    struct asn1_node algorithm_key_oid = asn1_get_next(algorithm.data, algorithm.len);
    if (!algorithm_key_oid.data) return X509_CERT_NOT_PARSABLE;
    if (!check_asn1_node(algorithm_key_oid, 0, ASN1_TAG_UNIVERSAL, ASN1_OBJECT_IDENTIFIER)) return X509_CERT_NOT_PARSABLE;
    // TODO: check the key type (algorithm), for EC it should be X963_KEY_TYPE_ECPUBKEY

    struct asn1_node algorithm_curve_oid = asn1_get_next(algorithm.data + algorithm_key_oid.header_len + algorithm_key_oid.len, algorithm.len - algorithm_key_oid.header_len - algorithm_key_oid.len);
    if (!algorithm_curve_oid.data) return X509_CERT_NOT_PARSABLE;
    if (!check_asn1_node(algorithm_curve_oid, 0, ASN1_TAG_UNIVERSAL, ASN1_OBJECT_IDENTIFIER)) return X509_CERT_NOT_PARSABLE;
    
    if (algorithm_curve_oid.len != curve.len) return X509_CERT_NOT_PARSABLE;
    if (memcmp(algorithm_curve_oid.data, curve.data, sizeof(X962_EC_KEY_OID)-1) != 0) return X509_CERT_MISMATCH;

    struct asn1_node subjectPublicKey = asn1_get_next(algorithm.data + algorithm.len, subjectPublicKeyInfo.len - algorithm.header_len - algorithm.len);
    if (!subjectPublicKey.data) return X509_CERT_NOT_PARSABLE;
    if (!check_asn1_node(subjectPublicKey, 0, ASN1_TAG_UNIVERSAL, ASN1_BIT_STRING)) return X509_CERT_NOT_PARSABLE;
    
    if (subjectPublicKey.len - 1 != public_key.len) return X509_CERT_MISMATCH;
    if (memcmp(subjectPublicKey.data+1, public_key.data, public_key.len) != 0) return X509_CERT_MISMATCH;

    return X509_LOADED;
}

static inline char x509_parse_priv_key(const unsigned char * priv_key, size_t n, Keys * keys_out, Vector * curve_oid_out) {
    assert(priv_key);
    assert(keys_out);
    assert(curve_oid_out);

    memset(keys_out, 0, sizeof(Keys));
    memset(curve_oid_out, 0, sizeof(Keys));


    struct asn1_node ECPrivateKey = asn1_get_next(priv_key, n);
    if (ECPrivateKey.data == NULL){
        wrong_format:
        free(keys_out->private_key.data); // free() doesn't mind null pointers
        free(keys_out->public_key.data);
        free(curve_oid_out->data);
        
        fprintf(stderr, "Error: Private key corrupted/not in DER format\n");
        return 0;
    }
    if (!check_asn1_node(ECPrivateKey, 1, ASN1_TAG_UNIVERSAL, ASN1_SEQUENCE)) {
        incorrect_encoding:
        free(keys_out->private_key.data);
        free(keys_out->public_key.data);
        free(curve_oid_out->data);

        fprintf(stderr, "Error: Private key incorrectly encoded!\n");
        return 0;
    }
    if (ECPrivateKey.header_len + ECPrivateKey.len != n) goto incorrect_encoding;

    struct asn1_node version = asn1_get_next(ECPrivateKey.data, ECPrivateKey.len);
    if (version.data == NULL) goto wrong_format;
    if (!check_asn1_node(version, 0, ASN1_TAG_UNIVERSAL, ASN1_INTEGER) || version.data[0] != 1) goto incorrect_encoding;

    struct asn1_node privateKey = asn1_get_next(version.data + version.len, ECPrivateKey.len - version.header_len - version.len);
    if (privateKey.data == NULL) goto wrong_format;
    if (!check_asn1_node(privateKey, 0, ASN1_TAG_UNIVERSAL, ASN1_OCTET_STRING)) goto incorrect_encoding;

    keys_out->private_key.len = privateKey.len;
    keys_out->private_key.data = malloc(privateKey.len);
    assert(keys_out->private_key.data);
    memcpy(keys_out->private_key.data, privateKey.data, privateKey.len);

    //if (version.header_len + version.len + private_key.header_len + private_key.len >= ECPrivateKey.len) return 0; // the rest are optional, but rfc5915 forces parameters

    struct asn1_node parameters = asn1_get_next(privateKey.data + privateKey.len, 
        ECPrivateKey.len - version.header_len - version.len - privateKey.header_len - privateKey.len);
    if (parameters.data == NULL) goto wrong_format;
    if (!check_asn1_node(parameters, 1, ASN1_TAG_CONTEXT_SPECIFIC, 0)) goto incorrect_encoding;

    struct asn1_node NamedCurve = asn1_get_next(parameters.data, parameters.len);
    if (NamedCurve.data == NULL) goto wrong_format;
    if (!check_asn1_node(NamedCurve, 0, ASN1_TAG_UNIVERSAL, ASN1_OBJECT_IDENTIFIER)) goto incorrect_encoding;
    
    curve_oid_out->len = NamedCurve.len;
    curve_oid_out->data = malloc(NamedCurve.len);
    assert(curve_oid_out->data);
    memcpy(curve_oid_out->data, NamedCurve.data, NamedCurve.len);

    // the rfc says that implementations must include the parameter, but only *should* include the public key
    if (version.header_len + version.len + 
        privateKey.header_len + privateKey.len +
        parameters.header_len + parameters.len >= ECPrivateKey.len) return 1;
    
    struct asn1_node publicKey = asn1_get_next(parameters.data + parameters.len, 
        ECPrivateKey.len -
        version.header_len - version.len -
        privateKey.header_len - privateKey.len -
        parameters.header_len - parameters.len
    );
    if (publicKey.data == NULL) goto wrong_format;
    if (!check_asn1_node(publicKey, 1, ASN1_TAG_CONTEXT_SPECIFIC, 1)) goto incorrect_encoding;

    struct asn1_node publicKey_inner = asn1_get_next(publicKey.data, publicKey.len);
    if (publicKey_inner.data == NULL) goto wrong_format;
    if (!check_asn1_node(publicKey_inner, 0, ASN1_TAG_UNIVERSAL, ASN1_BIT_STRING)) goto incorrect_encoding;

    if (publicKey_inner.data + publicKey_inner.len < ECPrivateKey.data + ECPrivateKey.len) goto incorrect_encoding;


    // public key for some reason begins with 00, so have to skip that
    keys_out->public_key.len = publicKey_inner.len - 1;
    keys_out->public_key.data = malloc(publicKey_inner.len - 1);
    assert(keys_out->public_key.data);
    memcpy(keys_out->public_key.data, publicKey_inner.data+1, publicKey_inner.len - 1);

    return 1;
}

enum x509_cert_status x509_load_cert(const unsigned char * pub_cert, size_t pub_len, const unsigned char * priv_cert, size_t priv_len, Keys * keys_out, enum x962_prime_curve_names * curve_out) {
    assert(pub_cert);
    assert(priv_cert);
    assert(keys_out);
    assert(curve_out);

    Keys keys = {0};
    Vector curve = {0};
    if (!x509_parse_priv_key(priv_cert, priv_len, &keys, &curve)) return X509_CERT_NOT_PARSABLE;
    if (!keys.public_key.data) fprintf(stderr, "Warn: X.509 private key doesn't have public key specified!\n");

    if (curve.len != sizeof(X962_EC_KEY_OID) - 1 || memcmp(curve.data, X962_EC_KEY_OID, sizeof(X962_EC_KEY_OID)-2) != 0) {
        fprintf(stderr, "Error: Currently we only support ANSI X9.62 prime elliptic curves for X.509 parsing, the specified private key doesn't appear to be using any of them\n");
        free(curve.data);
        free(keys.private_key.data);
        if (keys.public_key.data) free(keys.public_key.data);
        return X509_WRONG_CURVE;
    }

    *curve_out = ((unsigned char *)curve.data)[curve.len-1]; // TODO: this is a dirty hack to get just the ones we recognise, do some proper checking

    if (*curve_out == X962_PRIME_CURVE_NAME_PRIME256V1) {
        if (keys.public_key.data) {
            if (keys.public_key.len != SECP256_PUBKEY_SIZE) {
                fprintf(stderr, "Error: Public key specified in private key file is the wrong size for prime256v1 curve (%u bytes instead of %u)!\n", keys.public_key.len, SECP256_PUBKEY_SIZE);
                free(curve.data);
                free(keys.private_key.data);
                free(keys.public_key.data);
                return X509_WRONG_CURVE;
            }
        }
        struct secp_key calculated_public = secp256_get_public_key_from_private(keys.private_key.data);
        if (!keys.public_key.data) {
            keys.public_key.data = calculated_public.public_key;
            keys.public_key.len = SECP256_PUBKEY_SIZE;
        } else {
            for (int i = 0; i < SECP256_PUBKEY_SIZE; i++) {
                if (((unsigned char *)keys.public_key.data)[i] != calculated_public.public_key[i]) {
                    fprintf(stderr, "Error: Public key specified in private key file does not belong to the private key!\n");
                    free(curve.data);
                    free(keys.private_key.data);
                    free(keys.public_key.data);
                    free(calculated_public.public_key);
                    return X509_KEY_NOT_FOUND;
                }
            }
            free(calculated_public.public_key);
        }
    } else fprintf(stderr, "Warn: Can't check whether public key is correct in private key file - curve not yet implemented\n");

    enum x509_cert_status status = X509_CERT_NOT_PARSABLE;
    switch (status = x509_check_cert(pub_cert, pub_len, curve, keys.public_key)) {
        case X509_LOADED:
            break;
        case X509_CERT_MISMATCH:
            fprintf(stderr, "Error: Certificate does not match private key!\n");
            free(curve.data);
            free(keys.private_key.data);
            free(keys.public_key.data);
            return X509_CERT_MISMATCH;
        case X509_CERT_NOT_PARSABLE:
            fprintf(stderr, "Error: Certificate corrupted/not in DER format!\n");
            free(curve.data);
            free(keys.private_key.data);
            free(keys.public_key.data);
            return X509_CERT_NOT_PARSABLE;
        default:
            fprintf(stderr, "Error: Invalid/corrupted certificate provided!\n");
            free(curve.data);
            free(keys.private_key.data);
            free(keys.public_key.data);
            return status;
    }
    free(curve.data);

    *keys_out = keys;

    return X509_LOADED;
}