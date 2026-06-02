
#include "../include/ch512.h"
#include <string.h>
#include <stdlib.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

static void sha256_compress(uint32_t *h, const uint8_t *block) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, temp;
    int i;
    
    const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    
    for (i = 0; i < 16; i++) {
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = (w[i-15] >> 7) | (w[i-15] << 25);
        uint32_t s1 = (w[i-2] >> 17) | (w[i-2] << 15);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; h[7] = h[7];
    
    for (i = 0; i < 64; i++) {
        uint32_t S1 = (e >> 6) | (e << 26);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h[7] + S1 + ch + k[i] + w[i];
        uint32_t S0 = (a >> 2) | (a << 30);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        
        h[7] = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h[7];
}

static void sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint64_t bit_len = len * 8;
    uint8_t block[SHA256_BLOCK_SIZE];
    size_t offset = 0;
    int i;
    
    while (len >= SHA256_BLOCK_SIZE) {
        sha256_compress(h, data + offset);
        offset += SHA256_BLOCK_SIZE;
        len -= SHA256_BLOCK_SIZE;
    }
    
    memset(block, 0, SHA256_BLOCK_SIZE);
    memcpy(block, data + offset, len);
    block[len] = 0x80;
    
    if (len >= 56) {
        sha256_compress(h, block);
        memset(block, 0, SHA256_BLOCK_SIZE);
    }
    
    for (i = 0; i < 8; i++) block[56 + i] = (bit_len >> (56 - i*8)) & 0xFF;
    sha256_compress(h, block);
    
    for (i = 0; i < 8; i++) {
        hash[i*4] = (h[i] >> 24) & 0xFF;
        hash[i*4+1] = (h[i] >> 16) & 0xFF;
        hash[i*4+2] = (h[i] >> 8) & 0xFF;
        hash[i*4+3] = h[i] & 0xFF;
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac) {
    uint8_t k[SHA256_BLOCK_SIZE];
    uint8_t inner[SHA256_BLOCK_SIZE + data_len];
    uint8_t outer[SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE];
    int i;
    
    memset(k, 0, SHA256_BLOCK_SIZE);
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }
    
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) k[i] ^= 0x36;
    memcpy(inner, k, SHA256_BLOCK_SIZE);
    memcpy(inner + SHA256_BLOCK_SIZE, data, data_len);
    sha256(inner, SHA256_BLOCK_SIZE + data_len, mac);
    
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) k[i] ^= (0x36 ^ 0x5c);
    memcpy(outer, k, SHA256_BLOCK_SIZE);
    memcpy(outer + SHA256_BLOCK_SIZE, mac, SHA256_DIGEST_SIZE);
    sha256(outer, SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE, mac);
}

void kdf_pbkdf2(const char *password, size_t pass_len,
                const uint8_t *salt, size_t salt_len,
                uint8_t *output, size_t output_len) {
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t block[4];
    uint32_t block_num = 1;
    size_t out_pos = 0;
    
    while (out_pos < output_len) {
        uint8_t *salt_block = malloc(salt_len + 4);
        uint8_t *u = malloc(SHA256_DIGEST_SIZE);
        uint32_t iter;
        int i;
        
        memcpy(salt_block, salt, salt_len);
        block[0] = (block_num >> 24) & 0xFF;
        block[1] = (block_num >> 16) & 0xFF;
        block[2] = (block_num >> 8) & 0xFF;
        block[3] = block_num & 0xFF;
        memcpy(salt_block + salt_len, block, 4);
        
        hmac_sha256((uint8_t*)password, pass_len, salt_block, salt_len + 4, digest);
        memcpy(u, digest, SHA256_DIGEST_SIZE);
        
        for (iter = 1; iter < 600000; iter++) {
            hmac_sha256((uint8_t*)password, pass_len, u, SHA256_DIGEST_SIZE, digest);
            for (i = 0; i < SHA256_DIGEST_SIZE; i++) u[i] ^= digest[i];
        }
        
        size_t copy_len = SHA256_DIGEST_SIZE;
        if (out_pos + copy_len > output_len) copy_len = output_len - out_pos;
        memcpy(output + out_pos, u, copy_len);
        
        out_pos += copy_len;
        block_num++;
        
        free(salt_block);
        free(u);
    }
}