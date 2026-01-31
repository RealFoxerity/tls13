#ifndef X509_H
#define X509_H
#include "x9.62.h"
#include "memstructs.h"
#include <stddef.h>

enum x509_cert_status {
    X509_LOADED,
    X509_CERT_NOT_PARSABLE,
    X509_WRONG_CURVE,   // either cert has wrong curve spec
    X509_KEY_NOT_FOUND, // cannot find public/private keys in file
    X509_CERT_MISMATCH, // public key in pub_cert doesn't match the one in priv_cert
};
enum x509_cert_status x509_load_cert(const unsigned char * pub_cert, size_t pub_len, const unsigned char * priv_cert, size_t priv_len, Keys * keys_out, enum x962_prime_curve_names * curve_out);

#endif