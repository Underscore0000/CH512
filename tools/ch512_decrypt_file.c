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
    
    uint8_t salt[SALT_SIZE];
    uint8_t iv[GCM_IV_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    
    if (fread(salt, 1, SALT_SIZE, fin) != SALT_SIZE) { fprintf(stderr, "Corrupted\n"); return 1; }
    if (fread(iv, 1, GCM_IV_SIZE, fin) != GCM_IV_SIZE) { fprintf(stderr, "Corrupted\n"); return 1; }
    if (fread(tag, 1, GCM_TAG_SIZE, fin) != GCM_TAG_SIZE) { fprintf(stderr, "Corrupted\n"); return 1; }
    
    uint8_t key[KEY_SIZE];
    kdf_pbkdf2(argv[3], strlen(argv[3]), salt, SALT_SIZE, key, KEY_SIZE);
    
    fseek(fin, 0, SEEK_END);
    long cipher_len = ftell(fin) - (SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE);
    fseek(fin, SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE, SEEK_SET);
    
    uint8_t *cipher = malloc(cipher_len);
    uint8_t *plain = malloc(cipher_len);
    fread(cipher, 1, cipher_len, fin);
    
    ch512_ctx ctx;
    ch512_init(&ctx, key);
    
    int result = ch512_gcm_decrypt(&ctx, iv, GCM_IV_SIZE, cipher, cipher_len, plain, tag);
    
    if (result != 0) {
        fprintf(stderr, "DECRYPT FAILED: wrong password or corrupted file\n");
        free(cipher); free(plain);
        fclose(fin); fclose(fout);
        return 1;
    }
    
    fwrite(plain, 1, cipher_len, fout);
    printf("Decrypted %ld bytes successfully\n", cipher_len);
    
    free(cipher); free(plain);
    fclose(fin); fclose(fout);
    memset(key, 0, KEY_SIZE);
    ch512_zeroize_ctx(&ctx);
    return 0;
}