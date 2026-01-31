#ifndef SHA2_INTERNAL_H
#define SHA2_INTERNAL_H
#include "sha2.h"

// sha2_consts.c
extern const uint32_t sha1_iv       [SHA1_WORK_VARS];
extern const uint32_t sha224_iv     [SHA256_WORK_VARS];
extern const uint32_t sha256_iv     [SHA256_WORK_VARS];
extern const uint64_t sha384_iv     [SHA512_WORK_VARS];
extern const uint64_t sha512_iv     [SHA512_WORK_VARS];
extern const uint64_t sha512_224_iv [SHA512_WORK_VARS];
extern const uint64_t sha512_256_iv [SHA512_WORK_VARS];

#define GET_SHA1_CONST(t) (sha1_consts[(t)/20])
extern const uint32_t sha1_consts[SHA1_MESSAGE_SCHED_LEN];

extern const uint32_t sha256_consts[SHA256_MESSAGE_SCHED_LEN];
extern const uint64_t sha512_consts[SHA512_MESSAGE_SCHED_LEN];
#endif