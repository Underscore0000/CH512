#include "../include/ch512.h"
#include <string.h>
#include <stdlib.h>

static uint8_t gcm_H[16] = {0};
static uint8_t gcm_state[16] = {0};

static void gf128_mul(uint8_t *x, const uint8_t *y, const uint8_t *H) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    int i, j;
    memcpy(v, H, 16);
    memcpy(z, x, 16);
    for (i = 0; i < 128; i++) {
        uint8_t bit_mask = (y[i >> 3] >> (7 - (i & 7))) & 1;
        uint8_t select_mask = (uint8_t)(-bit_mask);
        for (j = 0; j < 16; j++) z[j] ^= v[j] & select_mask;
        uint8_t carry = v[15] & 1;
        for (j = 15; j >= 0; j--) {
            v[j] = (v[j] >> 1) | ((j > 0 ? (v[j-1] & 1) : 0) << 7);
        }
        if (carry) v[0] ^= 0xE1;
    }
    memcpy(x, z, 16);
}

static void ghash_init(const uint8_t *H) {
    memcpy(gcm_H, H, 16);
    memset(gcm_state, 0, 16);
}

static void ghash_update(const uint8_t *data, size_t len) {
    uint8_t block[16];
    size_t i;
    while (len >= 16) {
        for (i = 0; i < 16; i++) block[i] = gcm_state[i] ^ data[i];
        memcpy(gcm_state, block, 16);
        gf128_mul(gcm_state, gcm_state, gcm_H);
        data += 16; len -= 16;
    }
    if (len > 0) {
        memset(block, 0, 16);
        memcpy(block, data, len);
        for (i = 0; i < 16; i++) block[i] ^= gcm_state[i];
        memcpy(gcm_state, block, 16);
        gf128_mul(gcm_state, gcm_state, gcm_H);
    }
}

static void ghash_final(uint8_t *hash) {
    memcpy(hash, gcm_state, 16);
}

static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return (int)(((uint8_t)((-(diff != 0))) & 1));
}

void ch512_gcm_encrypt(const ch512_ctx *ctx, const uint8_t *iv, size_t iv_len,
                       const uint8_t *plain, size_t plain_len,
                       uint8_t *cipher, uint8_t *tag) {
    uint8_t H[16] = {0}, zero[16] = {0}, j0[16], counter[16], keystream[16];
    uint64_t len_block[2];
    size_t i, pos;
    int carry;
    ch512_encrypt_block(ctx, zero, H);
    ghash_init(H);
    memset(j0, 0, 16);
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[15] = 1;
    } else {
        ghash_update(iv, iv_len);
        len_block[0] = 0; len_block[1] = (uint64_t)iv_len * 8;
        for (i = 0; i < 8; i++) {
            uint8_t b0 = (len_block[0] >> (56 - i*8)) & 0xFF;
            uint8_t b1 = (len_block[1] >> (56 - i*8)) & 0xFF;
            ghash_update(&b0, 1); ghash_update(&b1, 1);
        }
        ghash_final(j0);
        ghash_init(H);
    }
    memcpy(counter, j0, 16);
    for (pos = 0; pos < plain_len; pos += 16) {
        carry = 1;
        for (i = 15; i >= 0 && carry; i--) {
            carry = (counter[i] + 1) >> 8;
            counter[i] = (counter[i] + 1) & 0xFF;
        }
        ch512_encrypt_block(ctx, counter, keystream);
        size_t chunk = (plain_len - pos < 16) ? (plain_len - pos) : 16;
        for (i = 0; i < chunk; i++) cipher[pos + i] = plain[pos + i] ^ keystream[i];
    }
    ghash_update(cipher, plain_len);
    len_block[0] = 0; len_block[1] = (uint64_t)plain_len * 8;
    for (i = 0; i < 8; i++) {
        uint8_t b0 = (len_block[0] >> (56 - i*8)) & 0xFF;
        uint8_t b1 = (len_block[1] >> (56 - i*8)) & 0xFF;
        ghash_update(&b0, 1); ghash_update(&b1, 1);
    }
    ghash_final(tag);
    ch512_encrypt_block(ctx, j0, keystream);
    for (i = 0; i < 16; i++) tag[i] ^= keystream[i];
}

int ch512_gcm_decrypt(const ch512_ctx *ctx, const uint8_t *iv, size_t iv_len,
                      const uint8_t *cipher, size_t cipher_len,
                      uint8_t *plain, const uint8_t *tag) {
    uint8_t H[16] = {0}, zero[16] = {0}, j0[16], counter[16], keystream[16];
    uint8_t computed_tag[16];
    uint64_t len_block[2];
    size_t i, pos;
    int carry;
    ch512_encrypt_block(ctx, zero, H);
    ghash_init(H);
    memset(j0, 0, 16);
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[15] = 1;
    } else {
        ghash_update(iv, iv_len);
        len_block[0] = 0; len_block[1] = (uint64_t)iv_len * 8;
        for (i = 0; i < 8; i++) {
            uint8_t b0 = (len_block[0] >> (56 - i*8)) & 0xFF;
            uint8_t b1 = (len_block[1] >> (56 - i*8)) & 0xFF;
            ghash_update(&b0, 1); ghash_update(&b1, 1);
        }
        ghash_final(j0);
        ghash_init(H);
    }
    ghash_update(cipher, cipher_len);
    len_block[0] = 0; len_block[1] = (uint64_t)cipher_len * 8;
    for (i = 0; i < 8; i++) {
        uint8_t b0 = (len_block[0] >> (56 - i*8)) & 0xFF;
        uint8_t b1 = (len_block[1] >> (56 - i*8)) & 0xFF;
        ghash_update(&b0, 1); ghash_update(&b1, 1);
    }
    ghash_final(computed_tag);
    ch512_encrypt_block(ctx, j0, keystream);
    for (i = 0; i < 16; i++) computed_tag[i] ^= keystream[i];
    if (constant_time_compare(tag, computed_tag, 16) != 0) return -1;
    memcpy(counter, j0, 16);
    for (pos = 0; pos < cipher_len; pos += 16) {
        carry = 1;
        for (i = 15; i >= 0 && carry; i--) {
            carry = (counter[i] + 1) >> 8;
            counter[i] = (counter[i] + 1) & 0xFF;
        }
        ch512_encrypt_block(ctx, counter, keystream);
        size_t chunk = (cipher_len - pos < 16) ? (cipher_len - pos) : 16;
        for (i = 0; i < chunk; i++) plain[pos + i] = cipher[pos + i] ^ keystream[i];
    }
    return 0;
}
