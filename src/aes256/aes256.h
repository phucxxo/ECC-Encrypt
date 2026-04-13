#ifndef AES256_H
#define AES256_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_LEN  16
#define AES_KEY_LEN    32
#define AES_ROUNDS     14

typedef struct {
    uint32_t round_key[4 * (AES_ROUNDS + 1)];
} aes256_ctx;

void aes256_init(aes256_ctx *ctx, const uint8_t key[AES_KEY_LEN]);

void aes256_encrypt_block(const aes256_ctx *ctx,
                          const uint8_t  in[AES_BLOCK_LEN],
                          uint8_t       out[AES_BLOCK_LEN]);

void aes256_decrypt_block(const aes256_ctx *ctx,
                          const uint8_t  in[AES_BLOCK_LEN],
                          uint8_t       out[AES_BLOCK_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* AES256_H */
