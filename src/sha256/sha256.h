#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_LEN  32
#define SHA256_BLOCK_LEN   64

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t  buffer[SHA256_BLOCK_LEN];
    uint32_t buf_len;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_LEN]);
void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_LEN]);
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[SHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHA256_H */
