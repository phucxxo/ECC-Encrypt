#ifndef AES256_H
#define AES256_H

/*
 * aes256.h — AES-256 Block Cipher (FIPS 197)
 *
 * Block size: 128 bits (16 bytes)
 * Key size:   256 bits (32 bytes)
 * Rounds:     14
 *
 * Provides ECB encrypt/decrypt of a single 16-byte block.
 * Mode of operation (GCM/CTR) is handled by gcm.c.
 */

#include <stdint.h>

#define AES_BLOCK_LEN  16
#define AES_KEY_LEN    32
#define AES_ROUNDS     14

/* Context holding the expanded round keys */
typedef struct {
    uint32_t round_key[4 * (AES_ROUNDS + 1)]; /* 60 words */
} aes256_ctx;

/* Key expansion: expand 32-byte key into round keys */
void aes256_init(aes256_ctx *ctx, const uint8_t key[AES_KEY_LEN]);

/* Encrypt a single 16-byte block (ECB) */
void aes256_encrypt_block(const aes256_ctx *ctx,
                          const uint8_t  in[AES_BLOCK_LEN],
                          uint8_t       out[AES_BLOCK_LEN]);

/* Decrypt a single 16-byte block (ECB) — not required by GCM/CTR,
 * but provided for completeness and potential CBC use */
void aes256_decrypt_block(const aes256_ctx *ctx,
                          const uint8_t  in[AES_BLOCK_LEN],
                          uint8_t       out[AES_BLOCK_LEN]);

#endif /* AES256_H */
