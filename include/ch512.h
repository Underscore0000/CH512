#ifndef CH512_H
#define CH512_H

#include <stdint.h>
#include <stddef.h>

#define CIPHER_NAME "CH512"
#define CIPHER_VERSION "2.0"
#define KEY_BITS 512
#define BLOCK_BITS 128
#define BLOCK_SIZE 16
#define KEY_SIZE 64
#define ROUNDS 32

#define SALT_SIZE 16
#define GCM_TAG_SIZE 16
#define GCM_IV_SIZE 12
#define KDF_ITERATIONS 600000

typedef struct {
    uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE];
    uint8_t sbox[256];
    uint8_t inv_sbox[256];
} ch512_ctx;

/* Core functions */
void ch512_init(ch512_ctx *ctx, const uint8_t *key);
void ch512_encrypt_block(const ch512_ctx *ctx, const uint8_t *plain, uint8_t *cipher);
void ch512_decrypt_block(const ch512_ctx *ctx, const uint8_t *cipher, uint8_t *plain);

/* CBC and CTR modes (legacy) */
void ch512_cbc_encrypt(const ch512_ctx *ctx, const uint8_t *iv,
                       const uint8_t *plain, uint8_t *cipher, size_t length);
void ch512_cbc_decrypt(const ch512_ctx *ctx, const uint8_t *iv,
                       const uint8_t *cipher, uint8_t *plain, size_t length);
void ch512_ctr_encrypt(const ch512_ctx *ctx, const uint8_t *iv,
                       const uint8_t *plain, uint8_t *cipher, size_t length);
void ch512_ctr_decrypt(const ch512_ctx *ctx, const uint8_t *iv,
                       const uint8_t *cipher, uint8_t *plain, size_t length);

/* KDF - PBKDF2-HMAC-SHA256 */
void kdf_pbkdf2(const char *password, size_t pass_len,
                const uint8_t *salt, size_t salt_len,
                uint8_t *output, size_t output_len);

/* GCM authenticated encryption */
void ch512_gcm_encrypt(const ch512_ctx *ctx,
                       const uint8_t *iv, size_t iv_len,
                       const uint8_t *plain, size_t plain_len,
                       uint8_t *cipher, uint8_t *tag);

int ch512_gcm_decrypt(const ch512_ctx *ctx,
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *cipher, size_t cipher_len,
                      uint8_t *plain, const uint8_t *tag);

/* Utility functions */
void ch512_zeroize_ctx(ch512_ctx *ctx);
void ch512_cipher_id(char *out, size_t out_len);
void pkcs7_pad(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
int pkcs7_unpad(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

#endif