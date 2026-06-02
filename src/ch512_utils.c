#include "../include/ch512.h"
#include <string.h>
#include <stdio.h>

void ch512_zeroize_ctx(ch512_ctx *ctx) {
    volatile uint8_t *p = (volatile uint8_t *)ctx;
    for (size_t i = 0; i < sizeof(ch512_ctx); i++) {
        p[i] = 0;
    }
}

void ch512_cipher_id(char *out, size_t out_len) {
    snprintf(out, out_len, "CH512 CrashHybrid 512/128 v1.0");
}

void xor_block(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        out[i] = a[i] ^ b[i];
    }
}

void copy_block(uint8_t *dst, const uint8_t *src) {
    memcpy(dst, src, BLOCK_SIZE);
}

void increment_counter(uint8_t *ctr, size_t len) {
    for (int i = len - 1; i >= 0; i--) {
        if (++ctr[i] != 0) break;
    }
}

void pkcs7_pad(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    size_t pad_len = BLOCK_SIZE - (in_len % BLOCK_SIZE);
    if (pad_len == 0) pad_len = BLOCK_SIZE;
    memcpy(out, in, in_len);
    for (size_t i = 0; i < pad_len; i++) {
        out[in_len + i] = (uint8_t)pad_len;
    }
    *out_len = in_len + pad_len;
}

int pkcs7_unpad(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    if (in_len % BLOCK_SIZE != 0 || in_len == 0) return -1;
    uint8_t pad_len = in[in_len - 1];
    if (pad_len == 0 || pad_len > BLOCK_SIZE) return -1;
    for (size_t i = in_len - pad_len; i < in_len; i++) {
        if (in[i] != pad_len) return -1;
    }
    *out_len = in_len - pad_len;
    memcpy(out, in, *out_len);
    return 0;
}