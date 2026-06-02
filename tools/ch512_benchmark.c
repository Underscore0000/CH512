#include "../include/ch512.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    uint8_t key[KEY_SIZE];
    uint8_t iv[BLOCK_SIZE];
    uint8_t plain[1024 * 1024];
    uint8_t cipher[1024 * 1024];
    
    memset(key, 0, KEY_SIZE);
    memset(iv, 0, BLOCK_SIZE);
    memset(plain, 0xAA, sizeof(plain));
    
    ch512_ctx ctx;
    ch512_init(&ctx, key);
    
    clock_t start = clock();
    ch512_cbc_encrypt(&ctx, iv, plain, cipher, sizeof(plain));
    clock_t end = clock();
    
    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    double mb = sizeof(plain) / (1024.0 * 1024.0);
    double throughput = mb / seconds;
    
    printf("CH512 Benchmark:\n");
    printf("  Data size: %.2f MB\n", mb);
    printf("  Time: %.3f seconds\n", seconds);
    printf("  Throughput: %.2f MB/s\n", throughput);
    
    ch512_zeroize_ctx(&ctx);
    
    return 0;
}