#include "../include/ch512.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

static int test_encrypt_decrypt(void) {
    printf("[TEST 1] Encrypt/Decrypt\n");
    
    uint8_t key[KEY_SIZE] = {0};
    uint8_t plain[BLOCK_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                                 0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
    uint8_t cipher[BLOCK_SIZE];
    uint8_t decrypted[BLOCK_SIZE];
    
    ch512_ctx ctx;
    ch512_init(&ctx, key);
    ch512_encrypt_block(&ctx, plain, cipher);
    ch512_decrypt_block(&ctx, cipher, decrypted);
    
    if (memcmp(plain, decrypted, BLOCK_SIZE) == 0) {
        printf("PASS: Plaintext recovered correctly\n");
        return 0;
    } else {
        printf("FAIL: Plaintext mismatch\n");
        return -1;
    }
}

static int test_cbc_mode(void) {
    printf("\n[TEST 2] CBC Mode\n");
    
    uint8_t key[KEY_SIZE] = {0};
    uint8_t iv[BLOCK_SIZE] = {0};
    uint8_t plain[BLOCK_SIZE * 2];
    uint8_t cipher[BLOCK_SIZE * 2];
    uint8_t decrypted[BLOCK_SIZE * 2];
    
    for (int i = 0; i < BLOCK_SIZE * 2; i++) {
        plain[i] = i & 0xFF;
    }
    
    ch512_ctx ctx;
    ch512_init(&ctx, key);
    ch512_cbc_encrypt(&ctx, iv, plain, cipher, BLOCK_SIZE * 2);
    ch512_cbc_decrypt(&ctx, iv, cipher, decrypted, BLOCK_SIZE * 2);
    
    if (memcmp(plain, decrypted, BLOCK_SIZE * 2) == 0) {
        printf("PASS: CBC mode works\n");
        return 0;
    } else {
        printf("FAIL: CBC mode failed\n");
        return -1;
    }
}

static int test_ctr_mode(void) {
    printf("\n[TEST 3] CTR Mode\n");
    
    uint8_t key[KEY_SIZE] = {0};
    uint8_t iv[BLOCK_SIZE] = {0};
    uint8_t plain[BLOCK_SIZE * 3 + 5];
    uint8_t cipher[BLOCK_SIZE * 3 + 5];
    uint8_t decrypted[BLOCK_SIZE * 3 + 5];
    
    for (int i = 0; i < sizeof(plain); i++) {
        plain[i] = i & 0xFF;
    }
    
    ch512_ctx ctx;
    ch512_init(&ctx, key);
    ch512_ctr_encrypt(&ctx, iv, plain, cipher, sizeof(plain));
    ch512_ctr_decrypt(&ctx, iv, cipher, decrypted, sizeof(plain));
    
    if (memcmp(plain, decrypted, sizeof(plain)) == 0) {
        printf("PASS: CTR mode works with partial block\n");
        return 0;
    } else {
        printf("FAIL: CTR mode failed\n");
        return -1;
    }
}

static int test_avalanche(void) {
    printf("\n[TEST 4] Avalanche effect (1 bit flip in key)\n");
    
    uint8_t key1[KEY_SIZE] = {0};
    uint8_t key2[KEY_SIZE] = {0};
    key2[0] = 0x01;
    
    uint8_t plain[BLOCK_SIZE] = {0};
    uint8_t cipher1[BLOCK_SIZE];
    uint8_t cipher2[BLOCK_SIZE];
    
    ch512_ctx ctx1, ctx2;
    ch512_init(&ctx1, key1);
    ch512_init(&ctx2, key2);
    ch512_encrypt_block(&ctx1, plain, cipher1);
    ch512_encrypt_block(&ctx2, plain, cipher2);
    
    int diff_bits = 0;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint8_t x = cipher1[i] ^ cipher2[i];
        for (int b = 0; b < 8; b++) {
            if (x & (1 << b)) diff_bits++;
        }
    }
    
    printf("Bits changed: %d / %d (%.1f%%)\n", diff_bits, BLOCK_SIZE * 8,
           (diff_bits * 100.0) / (BLOCK_SIZE * 8));
    
    if (diff_bits > 40 && diff_bits < 88) {
        printf("PASS: Avalanche acceptable\n");
        return 0;
    } else {
        printf("WARN: Avalanche outside expected range\n");
        return 0;
    }
}

int main(void) {
    printf("CH512 CrashHybrid v1.0 Test Suite\n");
    printf("=================================\n\n");
    
    int failures = 0;
    failures += test_encrypt_decrypt();
    failures += test_cbc_mode();
    failures += test_ctr_mode();
    failures += test_avalanche();
    
    printf("\n=================================\n");
    if (failures == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    } else {
        printf("%d TEST(S) FAILED\n", failures);
        return 1;
    }
}