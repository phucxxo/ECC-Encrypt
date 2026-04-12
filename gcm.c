/*
 * gcm.c — Triển khai AES-256-GCM (NIST SP 800-38D)
 *
 * Hai thành phần chính:
 *
 * 1. CTR Mode (Counter Mode):
 *    Biến AES block cipher thành stream cipher.
 *    counter_block = IV ‖ 0x00000001 (96-bit IV + 32-bit counter)
 *    keystream[i]  = AES_Enc(key, counter_block + i)
 *    C[i]          = P[i] XOR keystream[i]
 *
 * 2. GHASH (Galois Hash):
 *    Xác thực AAD và ciphertext trong GF(2^128).
 *    Đa thức tối giản: x^128 + x^7 + x^2 + x + 1
 *    GHASH(H, A, C) = tag
 *    H = AES_Enc(key, 0...0)
 *
 * Final tag = GHASH(H, AAD, C) XOR AES_Enc(key, IV ‖ 0x00000001)
 */

#include "gcm.h"
#include <string.h>
#include <stdint.h>

/* ========================================================
 * GHASH — Nhân trong GF(2^128)
 *
 * GF(2^128) với đa thức tối giản:
 *   f(x) = x^128 + x^7 + x^2 + x + 1
 *
 * Biểu diễn: mảng 16 bytes, byte[0] = MSB (big-endian bit)
 * ======================================================== */

/* Nhân x (128-bit) với H (128-bit) trong GF(2^128)
 * Thuật toán: "right-to-left" comb method
 * Mỗi block lưu big-endian: bit 0 là MSB của byte 0 */
static void ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    uint8_t v[16], z[16];
    memcpy(v, h, 16);
    memset(z, 0, 16);

    for (int i = 0; i < 16; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            /* Nếu bit tương ứng trong x = 1: z ^= v */
            if ((x[i] >> bit) & 1) {
                for (int k = 0; k < 16; k++) z[k] ^= v[k];
            }
            /* v = v * x  (shift phải 1 bit trong GF(2^128)) */
            uint8_t carry = v[15] & 1;  /* LSB của v (MSB của đa thức) */
            /* Shift right 1 bit */
            for (int k = 15; k > 0; k--)
                v[k] = (v[k] >> 1) | (v[k-1] << 7);
            v[0] >>= 1;
            /* Nếu carry: XOR với đa thức tối giản 0xe1 << 120 */
            if (carry) v[0] ^= 0xe1;
        }
    }
    memcpy(x, z, 16);
}

/*
 * GHASH: tính hash của dữ liệu AAD + Ciphertext
 * Theo NIST: xử lý AAD, sau đó C, sau đó length block
 *
 * ghash_update: XOR block vào state rồi nhân với H
 */
static void ghash_update_block(uint8_t state[16], const uint8_t block[16],
                                const uint8_t H[16]) {
    for (int i = 0; i < 16; i++) state[i] ^= block[i];
    ghash_mul(state, H);
}

/* Xử lý một luồng data (có thể không bội số 16 bytes) */
static void ghash_data(uint8_t state[16], const uint8_t *data, size_t len,
                       const uint8_t H[16]) {
    /* Xử lý từng block 16 bytes */
    while (len >= 16) {
        ghash_update_block(state, data, H);
        data += 16;
        len  -= 16;
    }
    /* Phần cuối < 16 bytes: padding bằng 0 */
    if (len > 0) {
        uint8_t pad_block[16];
        memset(pad_block, 0, 16);
        memcpy(pad_block, data, len);
        ghash_update_block(state, pad_block, H);
    }
}

/* ========================================================
 * CTR Mode
 * counter_block = IV(12 bytes) ‖ counter(4 bytes big-endian)
 * ======================================================== */

/* Tăng counter (4 bytes cuối, big-endian) */
static void ctr_inc(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++ctr[i]) break;
    }
}

/* XOR một đoạn data với keystream từ CTR mode */
static void ctr_crypt(const aes256_ctx *aes_ctx,
                      uint8_t ctr[16],
                      const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t keystream[AES_BLOCK_LEN];

    while (len >= AES_BLOCK_LEN) {
        aes256_encrypt_block(aes_ctx, ctr, keystream);
        ctr_inc(ctr);
        for (int i = 0; i < AES_BLOCK_LEN; i++) out[i] = in[i] ^ keystream[i];
        in  += AES_BLOCK_LEN;
        out += AES_BLOCK_LEN;
        len -= AES_BLOCK_LEN;
    }
    /* Phần cuối < 16 bytes */
    if (len > 0) {
        aes256_encrypt_block(aes_ctx, ctr, keystream);
        for (size_t i = 0; i < len; i++) out[i] = in[i] ^ keystream[i];
    }
}

/* ========================================================
 * GCM Encrypt
 * ======================================================== */
int gcm_encrypt(const uint8_t key[AES_KEY_LEN],
                const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad,   size_t aad_len,
                const uint8_t *plain, size_t plain_len,
                uint8_t       *cipher,
                uint8_t        tag[GCM_TAG_LEN]) {
    aes256_ctx aes_ctx;
    aes256_init(&aes_ctx, key);

    /* H = AES_Enc(key, 0^128) — hash subkey */
    uint8_t H[16];
    memset(H, 0, 16);
    aes256_encrypt_block(&aes_ctx, H, H);

    /* J0 = IV ‖ 0x00000001  (counter block ban đầu) */
    uint8_t J0[16];
    memcpy(J0, iv, GCM_IV_LEN);
    J0[12] = 0x00; J0[13] = 0x00; J0[14] = 0x00; J0[15] = 0x01;

    /* CTR counter bắt đầu từ J0+1 */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    ctr_inc(ctr);  /* J1 = IV ‖ 0x00000002 */

    /* Mã hoá plaintext */
    ctr_crypt(&aes_ctx, ctr, plain, cipher, plain_len);

    /* Tính GHASH(H, AAD, Cipher) */
    uint8_t ghash_state[16];
    memset(ghash_state, 0, 16);

    /* Xử lý AAD */
    ghash_data(ghash_state, aad, aad_len, H);

    /* Xử lý ciphertext */
    ghash_data(ghash_state, cipher, plain_len, H);

    /* Length block: len(AAD) ‖ len(C) — cả hai là 64-bit big-endian */
    uint8_t len_block[16];
    uint64_t aad_bits   = (uint64_t)aad_len   * 8;
    uint64_t plain_bits = (uint64_t)plain_len  * 8;
    for (int i = 7; i >= 0; i--) {
        len_block[i]     = (uint8_t)(aad_bits   >> ((7-i)*8));
        len_block[8 + i] = (uint8_t)(plain_bits >> ((7-i)*8));
    }
    ghash_update_block(ghash_state, len_block, H);

    /* Tag = GHASH_state XOR AES_Enc(key, J0) */
    uint8_t enc_j0[16];
    aes256_encrypt_block(&aes_ctx, J0, enc_j0);
    for (int i = 0; i < GCM_TAG_LEN; i++)
        tag[i] = ghash_state[i] ^ enc_j0[i];

    return 0;
}

/* ========================================================
 * GCM Decrypt + Verify
 * ======================================================== */
int gcm_decrypt(const uint8_t key[AES_KEY_LEN],
                const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad,    size_t aad_len,
                const uint8_t *cipher, size_t cipher_len,
                uint8_t       *plain,
                const uint8_t  tag[GCM_TAG_LEN]) {
    aes256_ctx aes_ctx;
    aes256_init(&aes_ctx, key);

    uint8_t H[16];
    memset(H, 0, 16);
    aes256_encrypt_block(&aes_ctx, H, H);

    uint8_t J0[16];
    memcpy(J0, iv, GCM_IV_LEN);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 0x01;

    /* Xác thực TRƯỚC khi giải mã (Encrypt-then-MAC style) */
    uint8_t ghash_state[16];
    memset(ghash_state, 0, 16);
    ghash_data(ghash_state, aad, aad_len, H);
    ghash_data(ghash_state, cipher, cipher_len, H);

    uint8_t len_block[16];
    uint64_t aad_bits    = (uint64_t)aad_len    * 8;
    uint64_t cipher_bits = (uint64_t)cipher_len * 8;
    for (int i = 7; i >= 0; i--) {
        len_block[i]     = (uint8_t)(aad_bits    >> ((7-i)*8));
        len_block[8 + i] = (uint8_t)(cipher_bits >> ((7-i)*8));
    }
    ghash_update_block(ghash_state, len_block, H);

    uint8_t enc_j0[16];
    aes256_encrypt_block(&aes_ctx, J0, enc_j0);

    uint8_t expected_tag[GCM_TAG_LEN];
    for (int i = 0; i < GCM_TAG_LEN; i++)
        expected_tag[i] = ghash_state[i] ^ enc_j0[i];

    /* So sánh constant-time (tránh timing attack) */
    uint8_t diff = 0;
    for (int i = 0; i < GCM_TAG_LEN; i++)
        diff |= (expected_tag[i] ^ tag[i]);
    if (diff != 0) return -1;  /* Tag không khớp → reject! */

    /* Giải mã */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    ctr_inc(ctr);
    ctr_crypt(&aes_ctx, ctr, cipher, plain, cipher_len);

    return 0;
}
