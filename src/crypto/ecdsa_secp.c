//https://www.secg.org/sec2-v2.pdf
//https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf
#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>


#include <stdint.h>

typedef unsigned _BitInt(256) uint256_t; // works only on x86 (intel) and (if gcc) on AArch64 (arm)
typedef unsigned __int128 uint128_t;