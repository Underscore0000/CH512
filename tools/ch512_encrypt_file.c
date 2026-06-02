#include "../include/ch512.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SALT_SIZE 16
#define GCM_TAG_SIZE 16
#define GCM_IV_SIZE 12

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input> <output> <password>\n", argv[0]);
        return 1;
    }
    
    FILE *fin = fopen(argv[1], "rb");
    FILE *fout = fopen(argv[2], "wb");
    if (!fin || !fout) { perror("File"); return 1; }
    
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    uint8_t salt[SALT_SIZE];
    uint8_t iv[GCM_IV_SIZE];
    FILE *urand = fopen("/dev/urandom", "rb");
    if (urand) {
        fread(salt, 1, SALT_SIZE, urand);
        fread(iv, 1, GCM_IV_SIZE, urand);
        fclose(urand);
    } else {
        memset(salt, 0, SALT_SIZE);
        memset(iv, 0, GCM_IV_SIZE);
        iv[11] = 1;
    }
    
    uint8_t key[KEY_SIZE];
    kdf_pbkdf2(argv[3], strlen(argv[3]), salt, SALT_SIZE, key, KEY_SIZE);
    
    ch512_ctx ctx;
    ch512_init(&ctx, key);
    
    uint8_t *plain = malloc(file_size);
    uint8_t *cipher = malloc(file_size);
    uint8_t tag[GCM_TAG_SIZE];
    
    fread(plain, 1, file_size, fin);
    ch512_gcm_encrypt(&ctx, iv, GCM_IV_SIZE, plain, file_size, cipher, tag);
    
    fwrite(salt, 1, SALT_SIZE, fout);
    fwrite(iv, 1, GCM_IV_SIZE, fout);
    fwrite(tag, 1, GCM_TAG_SIZE, fout);
    fwrite(cipher, 1, file_size, fout);
    
    printf("Encrypted %ld bytes with CH512-GCM\n", file_size);
    
    free(plain); free(cipher);
    fclose(fin); fclose(fout);
    memset(key, 0, KEY_SIZE);
    ch512_zeroize_ctx(&ctx);
    return 0;
}