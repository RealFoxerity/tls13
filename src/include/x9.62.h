#ifndef X962_H
#define X962_H

//https://www.rfc-editor.org/rfc/rfc3279 3 - ASN.1 Module
/*
    ASN.1 OID are... complicated...
    they are octet strings of concatenated categories encapsulated in ASN.1 Object Identifier (type 6) payload
    the ones we are interested in are the elliptic curve key types and elliptic curve named curves
    
    you can either look at rfc 3279 and be confused, or see https://oidref.com/1.2.840.10045 and click on the children fields

    what we are looking for is this
    <ANSI X9.62>:02:XX for key types
    <ANSI X9.62>:03:XX:XX for named curves
    <ANSI X9.62> in this case being 1.2.840.10045, or in hexadecimal 2a:86:48:ce:3d

    1.2.840.10045 being iso->member-body->us->ansi-x962

    and in case you were wondering how 1.2.840.10045 became 2a:86:48:ce:3d
    first 2 integers (x, y) are encoded: x*40 + y
    the rest that are <= 127 are directly written into bytes
    multiple byte ids are a bit more complicated, but make sense surprisingly
        you big endian encode the number, but highest bit of the first byte gets set to 1 to indicate continuation, 
        and the highest bit of the second is ignored


    so in the ANSI X9.62 case:
    1.2.840.10045
    1 * 40 + 2 = 42 = 0x2a
    840 = 0b110 1001000 -> 0b[1]000 0110 [0]100 1000 = 0x8648
    10045 = 0b1001110 0111101 -> 0b[1]100 1110 [0]011 1101 = 0xCE3D
    so 2a:86:48:ce:3d
    looks familiar?
*/
enum x962_subfields {
    X962_FIELD_TYPE = 1,
    x962_KEY_TYPE,
    X962_CURVES,
    X962_SIGNATURES,
    X962_MODULE
};
enum x962_key_types {
    X962_KEY_TYPE_ECPUBKEY = 1, // the only one defined
};
enum x962_curves {
    X962_CURVES_CHARACTERISTIC_TWO = 0, // c2 curves, not implemented by me
    X962_CURVES_PRIME
};

enum x962_c2_curve_names { // none implemented
    X962_C2_CURVE_NAME_C2PNB163V1 = 1,
    X962_C2_CURVE_NAME_C2PNB163V2,
    X962_C2_CURVE_NAME_C2PNB163V3,
    X962_C2_CURVE_NAME_C2PNB176W1,
    X962_C2_CURVE_NAME_C2TNB191V1,
    X962_C2_CURVE_NAME_C2TNB191V2,
    X962_C2_CURVE_NAME_C2TNB191V3,
    X962_C2_CURVE_NAME_C2ONB191V4,
    X962_C2_CURVE_NAME_C2ONB191V5,
    X962_C2_CURVE_NAME_C2PNB208W1,
    X962_C2_CURVE_NAME_C2TNB239V1,
    X962_C2_CURVE_NAME_C2TNB239V2,
    X962_C2_CURVE_NAME_C2TNB239V3,
    X962_C2_CURVE_NAME_C2ONB239V4,
    X962_C2_CURVE_NAME_C2ONB239V5,
    X962_C2_CURVE_NAME_C2PNB272W1,
    X962_C2_CURVE_NAME_C2PNB304W1,
    X962_C2_CURVE_NAME_C2TNB359V1,
    X962_C2_CURVE_NAME_C2PNB368W1,
    X962_C2_CURVE_NAME_C2TNB431R1,
};
enum x962_prime_curve_names {
    X962_PRIME_CURVE_NAME_PRIME192V1 = 1, // secp192r1, not implemented yet by me
    X962_PRIME_CURVE_NAME_PRIME192V2,
    X962_PRIME_CURVE_NAME_PRIME192V3,
    X962_PRIME_CURVE_NAME_PRIME239V1,
    X962_PRIME_CURVE_NAME_PRIME239V2,
    X962_PRIME_CURVE_NAME_PRIME239V3,
    X962_PRIME_CURVE_NAME_PRIME256V1, // secp256r1

};

#endif