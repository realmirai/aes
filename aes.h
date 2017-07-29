#ifndef __AES_h
#define __AES_h

#include <stddef.h>
#include <stdint.h>
#include "aes.constants.h"

struct aes_algospec {
    short Nk, Nr;
};

static const struct aes_algospec _algospec[3] = {
    (struct aes_algospec){4, 10},
    (struct aes_algospec){6, 12},
    (struct aes_algospec){8, 14}
};

#define _gmul(var, lambda) (_m##lambda[var])
#define rcon_word(x) (aes_rcon[x] << 24)
#define AESALGO(bits) (_algospec[bits / 64 - 2])
#define aes_enclen(length) (((length >> 4) << 4) + 16)

void aes_cipher(const int, const char *, const char *, char *);
void aes_invcipher(const int, const char *, const char *, char *);

void aes_ecbenc(const int, const char *, const size_t, const char *, char *);
size_t aes_ecbdec(const int, const char *, const size_t, const char *, char *);

void aes_cbcenc(const int, const char *, const size_t, const char*, const char *, char *);
size_t aes_cbcdec(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out);

void aes_pcbcenc(const int, const char *, const size_t, const char*, const char *, char *);
size_t aes_pcbcdec(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out);

void aes_cfbenc(const int, const char *, const size_t, const char*, const char *, char *);
size_t aes_cfbdec(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out);

void aes_ofbenc(const int, const char *, const size_t, const char*, const char *, char *);
size_t aes_ofbdec(const int bits, const char *in, const size_t length, const char *key, const char *iv, char *out);

#endif

