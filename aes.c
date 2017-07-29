#include <stdlib.h>
#include <string.h>
#include "aes.h"

#define Nb (4)

static inline uint32_t aes_rotword(uint32_t x) {
    return (x << 8) | (x >> 24);
}

static inline uint32_t aes_subword(uint32_t x) {
    return (aes_subs[x >> 24] << 24) |
    ((aes_subs[(x >> 16) & 0xff]) << 16) |
    ((aes_subs[(x >> 8) & 0xff]) << 8) |
    (aes_subs[x & 0xff]);
}

void aes_addroundkey(uint8_t *state, uint32_t *roundkey) {
    for (short i = 0; i < 16; i++) {
        state[i] = state[i] ^ ((roundkey[i / 4] >> (8 * (3 - i % 4))) & 0xff);
    }
}

void aes_subbytes(uint8_t *state) {
    for (short i = 0; i < 16; i++) {
        state[i] = aes_subs[state[i]];
    }
}

void aes_invsubbytes(uint8_t *state) {
    for (short i = 0; i < 16; i++) {
        state[i] = aes_invs[state[i]];
    }
}

void aes_shiftrows(uint8_t *state) {
    uint8_t tmp;
    // row #2
    tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;
    // row #3
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;
    // row #4
    tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
}

void aes_invshiftrows(uint8_t *state) {
    uint8_t tmp;
    // row #2
    tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;
    // row #3
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;
    // row #4
    tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

#define gmul(x, lam) (_gmul(x, lam))
void aes_mixcolumns(uint8_t *state) {
    uint8_t c[4];

    for (uint8_t *col = state; col < state + 16; col += 4) {
        c[0] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3];
        c[1] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3];
        c[2] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3);
        c[3] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2);

        col[0] = c[0];
        col[1] = c[1];
        col[2] = c[2];
        col[3] = c[3];
    }
}

void aes_invmixcolumns(uint8_t *state) {
    uint8_t c[4];

    for (uint8_t *col = state; col < state + 16; col += 4) {
        c[0] = gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3],  9);
        c[1] = gmul(col[0],  9) ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13);
        c[2] = gmul(col[0], 13) ^ gmul(col[1],  9) ^ gmul(col[2], 14) ^ gmul(col[3], 11);
        c[3] = gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2],  9) ^ gmul(col[3], 14);

        col[0] = c[0];
        col[1] = c[1];
        col[2] = c[2];
        col[3] = c[3];
    }
}
#undef gmul

void aes_keyexpansion(const short Nk, const short Nr, uint8_t *key, uint32_t *w) {
    uint32_t tmp;

    for (short i = 0; i < Nk; i++) {
        w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
    }
    for (short i = Nk; i < Nb * (Nr + 1); i++) {
        tmp = w[i - 1];
        if (i % Nk == 0) tmp = aes_subword(aes_rotword(tmp)) ^ rcon_word(i / Nk);
        else if ((Nk > 6) && (i % Nk == 4)) tmp = aes_subword(tmp);
        w[i] = w[i - Nk] ^ tmp;
    }
}

void aes_cipher(const int bits, const char *in, const char *key, char *out) {
    short Nk = AESALGO(bits).Nk,
        Nr = AESALGO(bits).Nr;

    uint8_t *state = (uint8_t *)out;
    memcpy(state, in, 4 * Nb);

    uint32_t *w = (uint32_t *)malloc(Nb * (Nr + 1) * sizeof(uint32_t));
    aes_keyexpansion(Nk, Nr, (uint8_t *)key, w);

    aes_addroundkey(state, &w[0]);
    for (short round = 1; round <  Nr; round++) {
        aes_subbytes(state);
        aes_shiftrows(state);
        aes_mixcolumns(state);
        aes_addroundkey(state, &w[round * Nb]);
    }
    aes_subbytes(state);
    aes_shiftrows(state);
    aes_addroundkey(state, &w[Nr * Nb]);
}

void aes_invcipher(const int bits, const char *in, const char *key, char *out) {
    short Nk = AESALGO(bits).Nk,
        Nr = AESALGO(bits).Nr;

    uint8_t *state = (uint8_t *)out;
    memcpy(state, in, 4 * Nb);

    uint32_t *w = (uint32_t *)malloc(Nb * (Nr + 1) * sizeof(uint32_t));
    aes_keyexpansion(Nk, Nr, (uint8_t *)key, w);

    aes_addroundkey(state, &w[Nr * Nb]);
    for (short round = Nr - 1; round > 0; round--) {
        aes_invshiftrows(state);
        aes_invsubbytes(state);
        aes_addroundkey(state, &w[round * Nb]);
        aes_invmixcolumns(state);
    }
    aes_invshiftrows(state);
    aes_invsubbytes(state);
    aes_addroundkey(state, &w[0]);
}
#undef Nb

const short aes_pkcs7padding(const char *in, const size_t length, char *blk) {
    short quot = length & 0x0f;
    memset(blk, 16 - quot, 16);
    if (quot > 0) memcpy(blk, in + length - quot, quot);
    return quot;
}

const size_t aes_calclength(const char *out, size_t length) {
    short quot = out[length - 1];
    for (const char *p = out + length - quot; p < out + length; p++)
        if (*p != quot) return length;
    return length - quot;
}

void aes_ecbenc(const int bits, const char *in, const size_t length, const char *key, char *out) {
    char blk[16];
    for (size_t d = 0; d + 15 < length; d += 16) {
        aes_cipher(bits, in + d, key, out + d);
    }
    short quot = aes_pkcs7padding(in, length, blk);
    aes_cipher(bits, blk, key, out + length - quot);
}

size_t aes_ecbdec(const int bits, const char *in, const size_t length, const char *key, char *out) {
    for (size_t d = 0; d + 15 < length; d += 16) {
        aes_invcipher(bits, in + d, key, out + d);
    }
    return aes_calclength(out, length);
}

void aes_cbcenc(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out) {
    const char *vector = iv;
    char blk[16];
    for (size_t d = 0; d + 15 < length; d += 16) {
        memcpy(blk, in + d, 16);
        for (short i = 0; i < 16; i++) blk[i] ^= vector[i];
        aes_cipher(bits, blk, key, out + d);
        vector = out + d;
    }
    short quot = aes_pkcs7padding(in, length, blk);
    for (short i = 0; i < 16; i++) blk[i] ^= vector[i];
    aes_cipher(bits, blk, key, out + length - quot);
}

size_t aes_cbcdec(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out) {
    const char *vector = iv;
    for (size_t d = 0; d + 15 < length; d += 16) {
        aes_invcipher(bits, in + d, key, out + d);
        for (short i = 0; i < 16; i++) *(out + d + i) ^= vector[i];
        vector = in + d;
    }
    return aes_calclength(out, length);
}

void aes_pcbcenc(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out) {
    char blk[16], vector[16];
    memcpy(vector, iv, 16);
    for (size_t d = 0; d + 15 < length; d += 16) {
        memcpy(blk, in + d, 16);
        for (short i = 0; i < 16; i++) blk[i] ^= vector[i];
        aes_cipher(bits, blk, key, out + d);
        for (short i = 0; i < 16; i++) vector[i] = vector[i] ^ blk[i] ^ *(out + d + i);
    }
    short quot = aes_pkcs7padding(in, length, blk);
    for (short i = 0; i < 16; i++) blk[i] ^= vector[i];
    aes_cipher(bits, blk, key, out + length - quot);
}

size_t aes_pcbcdec(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out) {
    char blk[16], vector[16];
    memcpy(vector, iv, 16);
    for (size_t d = 0; d + 15 < length; d += 16) {
        memcpy(blk, in + d, 16);
        aes_invcipher(bits, in + d, key, blk);
        for (short i = 0; i < 16; i++) *(out + d + i) = blk[i] ^ vector[i];
        for (short i = 0; i < 16; i++) vector[i] = *(in + d + i) ^ *(out + d + i);
    }
    return aes_calclength(out, length);
}

void aes_cfbenc(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out) {
    const char *vector = iv;
    char blk[16];
    for (size_t d = 0; d + 15 < length; d += 16) {
        aes_cipher(bits, vector, key, out + d);
        for (short i = 0; i < 16; i++) *(out + d + i) ^= *(in + d + i);
        vector = out + d;
    }
    short quot = aes_pkcs7padding(in, length, blk);
    aes_cipher(bits, vector, key, out + length - quot);
    for (short i = 0; i < 16; i++) *(out + length - quot + i) ^= blk[i];
}

size_t aes_cfbdec(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out) {
    const char *vector = iv;
    for (size_t d = 0; d + 15 < length; d += 16) {
        aes_cipher(bits, vector, key, out + d);
        for (short i = 0; i < 16; i++) *(out + d + i) ^= *(in + d + i);
        vector = in + d;
    }
    return aes_calclength(out, length);
}

void aes_ofbenc(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out) {
    const char *vector = iv;
    char blk[16];
    for (size_t d = 0; d + 15 < length; d += 16) {
        aes_cipher(bits, vector, key, out + d);
        vector = out + d;
    }
    short quot = aes_pkcs7padding(in, length, blk);
    aes_cipher(bits, vector, key, out + length - quot);
    for (size_t d = 0; d < ((length >> 4) << 4) ; d++) *(out + d) ^= *(in + d);
    for (short i = 0; i < 16; i++) *(out + length - quot + i) ^= blk[i];
}

size_t aes_ofbdec(const int bits, const char *in, size_t length, const char *key, const char *iv, char *out) {
    const char *vector = iv;
    for (size_t d = 0; d + 15 < length; d += 16) {
        aes_cipher(bits, vector, key, out + d);
        vector = out + d;
    }
    for (size_t d = 0; d < ((length >> 4) << 4) ; d++) *(out + d) ^= *(in + d);
    return aes_calclength(out, length);
}

