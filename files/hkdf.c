/*
 * hkdf.c — Triển khai HKDF-SHA256 (RFC 5869)
 *
 * Bước 1 — Extract:
 *   PRK = HMAC-SHA256(salt, IKM)
 *   → Biến IKM (có thể không đồng đều) thành pseudo-random key 32 bytes
 *
 * Bước 2 — Expand:
 *   T(0) = ""
 *   T(i) = HMAC-SHA256(PRK, T(i-1) ‖ info ‖ i)
 *   OKM  = T(1) ‖ T(2) ‖ ... (lấy đủ out_len bytes)
 */

#include "hkdf.h"
#include "sha256.h"
#include <string.h>

#define HASH_LEN  32   /* SHA-256 output = 32 bytes */

void hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t       *out,  size_t out_len) {

    /* ---- Bước 1: Extract ---- */
    uint8_t prk[HASH_LEN];

    /* Nếu không có salt → dùng chuỗi 0 dài HASH_LEN */
    uint8_t default_salt[HASH_LEN];
    if (!salt || salt_len == 0) {
        memset(default_salt, 0, HASH_LEN);
        salt     = default_salt;
        salt_len = HASH_LEN;
    }

    /* PRK = HMAC-SHA256(salt, IKM) */
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    /* ---- Bước 2: Expand ---- */
    uint8_t T[HASH_LEN];    /* T(i) hiện tại */
    uint8_t prev[HASH_LEN]; /* T(i-1) */
    size_t  generated = 0;
    uint8_t counter   = 1;

    memset(prev, 0, HASH_LEN);  /* T(0) = "" */
    uint8_t prev_len = 0;       /* Lần đầu không có T(i-1) */

    while (generated < out_len) {
        if (info_len > 256) info_len = 256;  /* giới hạn an toàn */

        /* Buffer tạm: T(i-1) ‖ info ‖ counter */
        uint8_t input[HASH_LEN + 256 + 1];
        size_t pos = 0;
        if (prev_len > 0) {
            memcpy(input + pos, prev, prev_len);
            pos += prev_len;
        }
        memcpy(input + pos, info, info_len);
        pos += info_len;
        input[pos++] = counter;

        hmac_sha256(prk, HASH_LEN, input, pos, T);

        /* Copy vào output */
        size_t copy_len = out_len - generated;
        if (copy_len > HASH_LEN) copy_len = HASH_LEN;
        memcpy(out + generated, T, copy_len);
        generated += copy_len;

        /* Chuẩn bị cho vòng tiếp */
        memcpy(prev, T, HASH_LEN);
        prev_len = HASH_LEN;
        counter++;
    }
}

void ecies_derive_keys(const uint8_t shared_x[32],
                       uint8_t k_enc[32],
                       uint8_t k_mac[32]) {
    /* Salt cố định cho ECIES — có thể thay bằng ephemeral nonce */
    static const uint8_t SALT[]     = "ECIES-P256-SHA256-v1";
    static const uint8_t INFO_ENC[] = "enc";
    static const uint8_t INFO_MAC[] = "mac";

    hkdf_sha256(shared_x, 32,
                SALT, sizeof(SALT) - 1,
                INFO_ENC, sizeof(INFO_ENC) - 1,
                k_enc, 32);

    hkdf_sha256(shared_x, 32,
                SALT, sizeof(SALT) - 1,
                INFO_MAC, sizeof(INFO_MAC) - 1,
                k_mac, 32);
}