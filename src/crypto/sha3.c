#include <stddef.h>
#include <stdlib.h>
#include "include/sha3.h"
#include <assert.h>
#include <string.h>

#include <stdio.h>


// TURNS OUT, SHA3-384 AND SHA384 ARE SOMETHING COMPLETELY DIFFERENT HAHAHAHAHA, this is useless

// source https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

// TODO: HEAVILY optimize, probably see below
// TODO: redo the entire thing so that it works on bytes instead of bits so we get about 8x the performance ...

// TODO: check whether this implementation works on big endian architecture, string_to_state and state_to_string probably won't

static const short keccak_b[] = {25, 50, 100, 200, 400, 800, 1600};
static const char  keccak_w[] = {1,   2,   4,   8,  16,  32,   64};
static const char  keccak_l[] = {0,   1,   2,   3,   4,   5,    6};

#define KECCAK_STATE_WIDTH 5
#define KECCAK_STATE_HEIGHT 5

#define SHA3_MODE (6)
#define SHA3_B (keccak_b[SHA3_MODE])
#define SHA3_W (keccak_w[SHA3_MODE])
#define SHA3_L (keccak_l[SHA3_MODE])

#define MOD(x, M) ((((x)%(M))+(M))%(M)) // negative numbers give negative % results

// inplace modify
static void keccak_step_theta(char state_array[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W]) {
    char state_array_C[KECCAK_STATE_WIDTH][SHA3_W];
    char state_array_D[KECCAK_STATE_WIDTH][SHA3_W];

    memset(state_array_C, 0, sizeof(state_array_C));
    memset(state_array_D, 0, sizeof(state_array_D));

    for (int x = 0; x < KECCAK_STATE_WIDTH; x++) {
        for (int z = 0; z < SHA3_W; z++) {
            state_array_C[x][z] = state_array[x][0][z] ^ state_array[x][1][z] ^ state_array[x][2][z] ^ state_array[x][3][z] ^ state_array[x][4][z]; // rewrite so that it's obvious it's the entire row
        }
    }
    for (int x = 0; x < KECCAK_STATE_WIDTH; x++) {
        for (int z = 0; z < SHA3_W; z++) {
            state_array_D[x][z] = state_array_C[MOD(x-1, KECCAK_STATE_WIDTH)][z] ^ state_array_C[MOD(x+1, KECCAK_STATE_WIDTH)][MOD(z-1, SHA3_W)];
        }
    }
    for (int x = 0; x < KECCAK_STATE_WIDTH; x++) {
        for (int y = 0; y < KECCAK_STATE_HEIGHT; y++) {
            for (int z = 0; z < SHA3_W; z++) {
                state_array[x][y][z] ^= state_array_D[x][z];
            }
        }
    }
} // first

// cannot be (or I at least don't see how) modified inplace for rho, pi, chi
#define KECCAK_RHO_STEPS 23
static void keccak_step_rho(char state_array[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W]) {
    char state_array_a[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W];
    memset(state_array_a, 0, sizeof(state_array_a));

    for (int z = 0; z < SHA3_W; z++) {
        state_array_a[0][0][z] = state_array[0][0][z];
    }
    int rho_x = 1, rho_y = 0;
    int temp = 0;
    for (int t = 0; t <= KECCAK_RHO_STEPS; t++) {
        for (int z = 0; z < SHA3_W; z++) {
            state_array_a[rho_x][rho_y][z] = state_array[rho_x][rho_y][MOD( (z-(t+1)*(t+2)/(2)), SHA3_W)];
        }
        temp = rho_x;
        rho_x = rho_y;
        rho_y = MOD((2*temp + 3*rho_y), KECCAK_STATE_HEIGHT);
    }
    memcpy(state_array, state_array_a, sizeof(state_array_a));
} // second

static void keccak_step_pi(char state_array[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W]) {
    char state_array_a[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W];
    memset(state_array_a, 0, sizeof(state_array_a));

    for (int x = 0; x < KECCAK_STATE_WIDTH; x++) {
        for (int y = 0; y < KECCAK_STATE_HEIGHT; y++) {
            for (int z = 0; z < SHA3_W; z++) {
                state_array_a[x][y][z] = state_array[MOD( x + 3*y , KECCAK_STATE_WIDTH)][x][z];
            }
        }
    }
    memcpy(state_array, state_array_a, sizeof(state_array_a));
} // third
static void keccak_step_chi(char state_array[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W]) {
    char state_array_a[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W];
    memset(state_array_a, 0, sizeof(state_array_a));

    for (int x = 0; x < KECCAK_STATE_WIDTH; x++) {
        for (int y = 0; y < KECCAK_STATE_HEIGHT; y++) {
            for (int z = 0; z < SHA3_W; z++) {
                state_array_a[x][y][z] = state_array[x][y][z] ^ ((state_array[MOD(x+1, KECCAK_STATE_WIDTH)][y][z]^1)&state_array[MOD(x+2, KECCAK_STATE_WIDTH)][y][z]);
            }
        }
    }
    memcpy(state_array, state_array_a, sizeof(state_array_a));
} // fourth

//static char keccak_step_rc(int t) { // this is so dumb i'm not even going to entertain testing this
//    if (MOD(t, 255) == 0) return 1;
//    char R[9] = {1, 0, 0, 0, 0, 0, 0, 0, 0};
//
//    for (int i = 1; i <= MOD(t, 255); i++) {
//        memcpy(&R[1], R, 8); // R = 0 || R
//        R[0] = 0;
//
//        R[0] ^= R[8];
//        R[4] ^= R[8];
//        R[5] ^= R[8];
//        R[6] ^= R[8];
//        // Trunc8(R) is handled by the memcpy
//    }
//    return R[0];
//}


static char keccak_step_rc(int t) {
    static char bits[] = {
        1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0,
    1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0,
    1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1,
    0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1,
    0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0,
    1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0,
    0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1,
    1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1,
    0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1,
    1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1,
    1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0,
    1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1,
    1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1};
    return bits[MOD(t,255)];
}

static int powi(int x, int p) {
    if (p == 0) return 1;
    int out = x;
    for (int i = 1; i < p; i++) out*=x;
    return out;
}

static void keccak_step_iota(char state_array[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W], int round_factor) {
    char RC[SHA3_W];
    memset(RC, 0, sizeof(RC));
    for (int j = 0; j <= SHA3_L; j++) {
        RC[powi(2, j) - 1] = keccak_step_rc(j + 7*round_factor);
    }
    for (int z = 0; z < SHA3_W; z++) {
        state_array[0][0][z] ^= RC[z];
    }

} // fifth


static char get_bit_keccak(char * array, int w, int x, int y, int z) {
    int bit_n = w*(KECCAK_STATE_HEIGHT*y + x) + z;
    char byte = array[bit_n/8];
    // lowest order bit is the first in a bit stream
    char out = 0;
    out = (byte & (1 << (bit_n%8))) >> (bit_n%8);
    return out;
}

static void set_bit_keccak(char * array, int w, int x, int y, int z, int bit) { // presumes array is zeroed out
    int bit_n = w*(KECCAK_STATE_HEIGHT*y + x) + z;
    char delta = 0;
    delta = bit << (bit_n%8);
    array[bit_n/8] |= delta;
}

static void string_to_state(char state_out[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W], char * string) {
    for (int x = 0; x < KECCAK_STATE_WIDTH; x++) {
        for (int y = 0; y < KECCAK_STATE_HEIGHT; y ++) {
            for (int z = 0; z < SHA3_W; z++) {
                state_out[x][y][z] = get_bit_keccak(string, SHA3_W, x, y, z);
            }
        }
    }
}

static void state_to_string(char state_array[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W], char * string_out) {
    memset(string_out, 0, 200);

    for (int x = 0; x < KECCAK_STATE_WIDTH; x++) {
        for (int y = 0; y < KECCAK_STATE_HEIGHT; y++) {
            for (int z = 0; z < SHA3_W; z++) {
                set_bit_keccak(string_out, SHA3_W, x, y, z, state_array[x][y][z]);
            }
        }
    }
}

static void keccak_round(char state_array[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W], int round_factor) {
    keccak_step_theta(state_array);
    keccak_step_rho(state_array);
    keccak_step_pi(state_array);
    keccak_step_chi(state_array);
    keccak_step_iota(state_array, round_factor);
}


static size_t pad10_star_1(char ** input, size_t original_len, int block_size) { // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf page 19 (27)
    int j = MOD(-(long long)original_len*8 - 2 - 2, block_size*8); // -2 for 01 append, -2 for ones on both sides

    size_t new_len = original_len + j/8 + ((j%8 != 0)?1:0);
    assert((*input = realloc(*input, new_len)));

    memset(&(*input)[original_len], 0, new_len-original_len);

    for (int i = original_len; i < new_len; i++) {
        if (i == original_len) {
            (*input)[i] = 0b0000110;
            //input[i] = 0b00000001;
        } else if (i == new_len - 1) {
            (*input)[i] = 0b10000000;
        }
    }
    return new_len;
}

static void do_keccak(char * string, int rounds, char * string_out) {
    char state[KECCAK_STATE_WIDTH][KECCAK_STATE_HEIGHT][SHA3_W];
    memset(state, 0, sizeof(state));
    string_to_state(state, string);

    for (int ir = 12 + 2*SHA3_L - rounds; ir <= 12 + 2*SHA3_L - 1; ir++) { // in sha384 from 0 to 23 incl -> 24 rounds
        keccak_round(state, ir);
    }

    state_to_string(state, string_out);
}

static void xor_string(char * string_a, char * string_b, size_t len) { // string_a will be xored with string_b inplace
    for (int i = 0; i < len; i++) {
        string_a[i] ^= string_b[i];
    }
}

static void keccak_sponge_sha3(const unsigned char * string, int string_len, int hash_length, unsigned char * string_out) {

    int r = SHA3_B-hash_length*2;
    r /= 8; // bytes

    char * new_input = malloc(string_len);
    assert(new_input);
    memset(new_input, 0, string_len);
    memcpy(new_input, string, string_len);

    string_len = pad10_star_1(&new_input, string_len, r);

    int n = string_len / r;

    //int c = SHA3_B/8 - r;

    char s[SHA3_B/8];
    char s2[SHA3_B/8];
    char temp[SHA3_B/8];

    char z[hash_length/8 + r]; // better be safe

    int z_off = 0;

    memset(s, 0, sizeof(s));
    memset(s2, 0, sizeof(s2));
    memset(temp, 0, sizeof(temp));
    memset(z, 0, hash_length/8 + r);

    for (int i = 0; i < n; i++) {
        memset(temp, 0, sizeof(temp));
        memcpy(temp, &new_input[i*r], r);

        xor_string(s, temp, SHA3_B/8);

        do_keccak(s, 12+2*SHA3_L, s2);
        memcpy(s, s2, sizeof(s));

    }

    while(1) {
        memcpy(&z[z_off], s, r);
        z_off += r;

        if (hash_length/8 <= z_off) {
            memcpy(string_out, z, hash_length/8);
            break;
        }

        do_keccak(s, 12+2*SHA3_L, s2);
        memcpy(s, s2, sizeof(s));
    }
    free(new_input);
    return;
}

void sha3_sum_internal(unsigned char * hash_out, int hash_len_bits, const unsigned char * input, size_t input_len) { // have to copy the array due to needed padding, TODO: rewrite to not need that
    keccak_sponge_sha3(input, input_len, hash_len_bits, hash_out); // sha384...
}

void sha3_224_sum(unsigned char * hash_out, const unsigned char * input, int input_len) {
    sha3_sum_internal(hash_out, 224, input, input_len);
}
void sha3_256_sum(unsigned char * hash_out, const unsigned char * input, int input_len) {
    sha3_sum_internal(hash_out, 256, input, input_len);
}
void sha3_384_sum(unsigned char * hash_out, const unsigned char * input, int input_len) {
    sha3_sum_internal(hash_out, 384, input, input_len);
}
void sha3_512_sum(unsigned char * hash_out, const unsigned char * input, int input_len) {
    sha3_sum_internal(hash_out, 512, input, input_len);
}