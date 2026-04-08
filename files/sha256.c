/*
 * sha256.c — Triển khai SHA-256 theo FIPS 180-4
 *
 * Thuật toán:
 *   1. Padding: thêm bit 1, rồi 0s, rồi độ dài 64-bit big-endian
 *      để tổng độ dài ≡ 0 (mod 512 bits)
 *   2. Xử lý từng block 512-bit qua 64 vòng lặp compression
 *   3. Output: nối 8 từ trạng thái (big-endian)
 */

#include "sha256.h"
#include <string.h>

/* ---- Hằng số K (căn bậc 3 của 64 số nguyên tố đầu tiên) ---- */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ---- Macro tiện ích ---- */
#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32-(n))))
#define CH(e,f,g)   (((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a,b,c)  (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define EP0(a)      (ROTR(a, 2)  ^ ROTR(a,13) ^ ROTR(a,22))
#define EP1(e)      (ROTR(e, 6)  ^ ROTR(e,11) ^ ROTR(e,25))
#define SIG0(x)     (ROTR(x, 7)  ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x)     (ROTR(x,17)  ^ ROTR(x,19) ^ ((x) >> 10))

/* ---- Giá trị khởi tạo H (căn bậc 2 của 8 số nguyên tố đầu) ---- */
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* ---- Xử lý một block 64-byte ---- */
static void sha256_process_block(sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;

    /* Chuẩn bị message schedule W */
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i*4]     << 24) |
               ((uint32_t)block[i*4 + 1] << 16) |
               ((uint32_t)block[i*4 + 2] <<  8) |
               ((uint32_t)block[i*4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }

    /* Khởi tạo working variables từ state hiện tại */
    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    /* 64 vòng compression */
    for (int i = 0; i < 64; i++) {
        T1 = h + EP1(e) + CH(e,f,g) + K[i] + W[i];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }

    /* Cập nhật state */
    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

/* ========================================================
 * API
 * ======================================================== */

void sha256_init(sha256_ctx *ctx) {
    memcpy(ctx->state, H0, sizeof(H0));
    ctx->bit_count = 0;
    ctx->buf_len   = 0;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bit_count += (uint64_t)len * 8;

    while (len > 0) {
        uint32_t space = SHA256_BLOCK_LEN - ctx->buf_len;
        uint32_t take  = (len < space) ? (uint32_t)len : space;
        memcpy(ctx->buffer + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len  -= take;

        if (ctx->buf_len == SHA256_BLOCK_LEN) {
            sha256_process_block(ctx, ctx->buffer);
            ctx->buf_len = 0;
        }
    }
}

void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_LEN]) {
    /* Lưu độ dài gốc (tính bằng bits) TRƯỚC khi thêm padding */
    uint64_t original_bit_count = ctx->bit_count;

    /* Thêm byte 0x80 (bit '1' tiếp theo sau dữ liệu) */
    uint8_t pad_byte = 0x80;
    sha256_update(ctx, &pad_byte, 1);

    /* Thêm 0x00 cho đến khi buffer có 56 bytes (còn 8 bytes cho length field) */
    uint8_t zero = 0x00;
    while (ctx->buf_len != 56)
        sha256_update(ctx, &zero, 1);

    /* Append độ dài gốc dưới dạng 64-bit big-endian (tính bằng bits)
     * RFC: length field = số bits của message gốc (không tính padding) */
    uint8_t len_bytes[8];
    for (int i = 7; i >= 0; i--) {
        len_bytes[i] = (uint8_t)(original_bit_count & 0xff);
        original_bit_count >>= 8;
    }
    sha256_update(ctx, len_bytes, 8);

    /* Xuất digest big-endian: state[0] MSB trước */
    for (int i = 0; i < 8; i++) {
        digest[i*4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        digest[i*4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_LEN]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* ========================================================
 * HMAC-SHA256
 * RFC 2104: HMAC(K,m) = H((K' ⊕ opad) ‖ H((K' ⊕ ipad) ‖ m))
 * K' = K nếu |K| ≤ 64, ngược lại K' = H(K)
 * ======================================================== */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[SHA256_DIGEST_LEN]) {
    uint8_t k_prime[SHA256_BLOCK_LEN];
    uint8_t ipad[SHA256_BLOCK_LEN], opad[SHA256_BLOCK_LEN];
    sha256_ctx ctx;
    uint8_t inner[SHA256_DIGEST_LEN];

    /* Chuẩn bị K' */
    memset(k_prime, 0, sizeof(k_prime));
    if (key_len > SHA256_BLOCK_LEN) {
        sha256(key, key_len, k_prime);
    } else {
        memcpy(k_prime, key, key_len);
    }

    /* ipad = K' XOR 0x36..., opad = K' XOR 0x5c... */
    for (int i = 0; i < SHA256_BLOCK_LEN; i++) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    /* inner = H(ipad ‖ msg) */
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, SHA256_BLOCK_LEN);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, inner);

    /* mac = H(opad ‖ inner) */
    sha256_init(&ctx);
    sha256_update(&ctx, opad, SHA256_BLOCK_LEN);
    sha256_update(&ctx, inner, SHA256_DIGEST_LEN);
    sha256_final(&ctx, mac);
}
