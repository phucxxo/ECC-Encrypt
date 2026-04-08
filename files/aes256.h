#ifndef AES256_H
#define AES256_H

/*
 * aes256.h — AES-256 Block Cipher (FIPS 197)
 *
 * Block size: 128 bits (16 bytes)
 * Key size:   256 bits (32 bytes)
 * Rounds:     14
 *
 * Chỉ cung cấp ECB encrypt/decrypt một block (16 bytes).
 * Mode of operation (GCM/CTR) được xử lý bởi module gcm.c.
 */

#include <stdint.h>

#define AES_BLOCK_LEN  16
#define AES_KEY_LEN    32
#define AES_ROUNDS     14

/* Context lưu round keys đã được mở rộng (expanded) */
typedef struct {
    uint32_t round_key[4 * (AES_ROUNDS + 1)]; /* 60 words */
} aes256_ctx;

/* Khởi tạo: mở rộng key */
void aes256_init(aes256_ctx *ctx, const uint8_t key[AES_KEY_LEN]);

/* Mã hoá một block 16 bytes (ECB) */
void aes256_encrypt_block(const aes256_ctx *ctx,
                          const uint8_t  in[AES_BLOCK_LEN],
                          uint8_t       out[AES_BLOCK_LEN]);

/* Giải mã một block 16 bytes (ECB) — cần cho AES-GCM nếu dùng CBC,
 * không cần cho CTR/GCM nhưng để đầy đủ */
void aes256_decrypt_block(const aes256_ctx *ctx,
                          const uint8_t  in[AES_BLOCK_LEN],
                          uint8_t       out[AES_BLOCK_LEN]);

#endif /* AES256_H */
