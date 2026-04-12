#ifndef SHA256_H
#define SHA256_H

/*
 * sha256.h — Triển khai SHA-256 (FIPS 180-4)
 *
 * Dùng cho: HKDF (key derivation), HMAC
 * Output: 32 bytes (256 bits)
 */

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_LEN  32
#define SHA256_BLOCK_LEN   64

/* Trạng thái SHA-256 */
typedef struct {
    uint32_t state[8];      /* 8 từ 32-bit (a,b,c,d,e,f,g,h) */
    uint64_t bit_count;     /* Tổng số bit đã xử lý */
    uint8_t  buffer[SHA256_BLOCK_LEN];
    uint32_t buf_len;       /* Số bytes trong buffer */
} sha256_ctx;

/* ---- API ---- */

/* Khởi tạo context */
void sha256_init(sha256_ctx *ctx);

/* Nạp dữ liệu (có thể gọi nhiều lần) */
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);

/* Hoàn tất và lấy digest (32 bytes) */
void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_LEN]);

/* Hàm tiện lợi: hash toàn bộ một buffer */
void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_LEN]);

/* HMAC-SHA256 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[SHA256_DIGEST_LEN]);

#endif /* SHA256_H */