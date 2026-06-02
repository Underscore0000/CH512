#include "../include/ch512.h"
#include <string.h>

static void xor_block(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static void copy_block(uint8_t *dst, const uint8_t *src) {
    memcpy(dst, src, BLOCK_SIZE);
}

static void increment_counter(uint8_t *ctr) {
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        if (++ctr[i] != 0) break;
    }
}

void ch512_cbc_encrypt(const ch512_ctx *ctx, const uint8_t *iv,
                       const uint8_t *plain, uint8_t *cipher, size_t length) {
    if (length % BLOCK_SIZE != 0) return;
    
    uint8_t prev[BLOCK_SIZE];
    copy_block(prev, iv);
    
    for (size_t i = 0; i < length; i += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        xor_block(block, plain + i, prev);
        ch512_encrypt_block(ctx, block, cipher + i);
        copy_block(prev, cipher + i);
    }
}

void ch512_cbc_decrypt(const ch512_ctx *ctx, const uint8_t *iv,
                       const uint8_t *cipher, uint8_t *plain, size_t length) {
    if (length % BLOCK_SIZE != 0) return;
    
    uint8_t prev[BLOCK_SIZE];
    copy_block(prev, iv);
    
    for (size_t i = 0; i < length; i += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        ch512_decrypt_block(ctx, cipher + i, block);
        xor_block(plain + i, block, prev);
        copy_block(prev, cipher + i);
    }
}

void ch512_ctr_encrypt(const ch512_ctx *ctx, const uint8_t *iv,
                       const uint8_t *plain, uint8_t *cipher, size_t length) {
    uint8_t counter[BLOCK_SIZE];
    copy_block(counter, iv);
    
    for (size_t i = 0; i < length; i += BLOCK_SIZE) {
        uint8_t keystream[BLOCK_SIZE];
        size_t chunk = (length - i < BLOCK_SIZE) ? (length - i) : BLOCK_SIZE;
        
        ch512_encrypt_block(ctx, counter, keystream);
        
        for (size_t j = 0; j < chunk; j++) {
            cipher[i + j] = plain[i + j] ^ keystream[j];
        }
        
        increment_counter(counter);
    }
}

void ch512_ctr_decrypt(const ch512_ctx *ctx, const uint8_t *iv,
                       const uint8_t *cipher, uint8_t *plain, size_t length) {
    /* CTR decryption = CTR encryption */
    ch512_ctr_encrypt(ctx, iv, cipher, plain, length);
}