/*
 * ecies.c — Triển khai ECIES
 *
 * Luồng mã hoá:
 *   1. Sinh ephemeral key pair (r, R=r·G) từ random_key
 *   2. ECDH: shared_x = (r · Q_Bob).x
 *   3. KDF:  k_enc = HKDF(shared_x, "enc")
 *   4. GCM:  cipher, tag = AES-256-GCM(k_enc, iv, plaintext)
 *   5. Đóng gói: R ‖ IV ‖ len ‖ cipher ‖ tag
 *
 * Luồng giải mã:
 *   1. Đọc R từ gói tin
 *   2. ECDH: shared_x = (d_Bob · R).x
 *   3. KDF:  k_enc = HKDF(shared_x, "enc")
 *   4. GCM:  plain = AES-256-GCM-Decrypt(k_enc, iv, cipher, tag)
 *      → Nếu tag sai: reject ngay
 */

#include "ecies.h"
#include "ecc.h"
#include "hkdf.h"
#include "gcm.h"
#include <string.h>
#include <stdint.h>

/* Ghi uint32 big-endian vào buffer */
static void write_u32_be(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val >> 24);
    buf[1] = (uint8_t)(val >> 16);
    buf[2] = (uint8_t)(val >>  8);
    buf[3] = (uint8_t)(val      );
}

/* Đọc uint32 big-endian từ buffer */
static uint32_t read_u32_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
}

/* ========================================================
 * ecies_encrypt
 * ======================================================== */
int ecies_encrypt(const uint8_t  receiver_pub[65],
                  const uint8_t  random_key[32],
                  const uint8_t  random_iv[12],
                  const uint8_t *plaintext, size_t plain_len,
                  uint8_t       *out_buf,   size_t *out_len) {

    /* ---- Bước 1: Sinh ephemeral key pair (r, R) ---- */
    uint8_t eph_priv[32];
    uint8_t eph_pub[65];    /* R = r · G */

    ecc_keygen(random_key, eph_priv, eph_pub);

    /* ---- Bước 2: ECDH → shared_x = (r · Q_Bob).x ---- */
    uint8_t shared_x[32];
    if (ecc_ecdh(eph_priv, receiver_pub, shared_x) != 0) {
        return -1;  /* Public key không hợp lệ */
    }

    /* ---- Bước 3: KDF → k_enc ---- */
    uint8_t k_enc[32], k_mac[32];
    ecies_derive_keys(shared_x, k_enc, k_mac);
    /* k_mac không dùng trong GCM (GCM tự xác thực) */
    (void)k_mac;

    /* ---- Bước 4: AES-256-GCM Encrypt ---- */
    /* AAD: dùng ephemeral public key làm additional data
     * → xác thực rằng eph_pub trong gói tin không bị thay đổi */
    uint8_t *cipher_ptr = out_buf + 65 + 12 + 4;
    uint8_t  tag[GCM_TAG_LEN];

    gcm_encrypt(k_enc, random_iv,
                eph_pub, 65,          /* AAD = ephemeral public key */
                plaintext, plain_len,
                cipher_ptr,
                tag);

    /* ---- Bước 5: Đóng gói gói tin ---- */
    uint8_t *p = out_buf;

    /* R (65 bytes) */
    memcpy(p, eph_pub, 65);  p += 65;

    /* IV (12 bytes) */
    memcpy(p, random_iv, 12); p += 12;

    /* cipher_len (4 bytes, big-endian) */
    write_u32_be(p, (uint32_t)plain_len); p += 4;

    /* Ciphertext đã được ghi vào cipher_ptr (= p ban đầu + 65+12+4) */
    p += plain_len;

    /* Tag (16 bytes) */
    memcpy(p, tag, GCM_TAG_LEN);

    *out_len = 65 + 12 + 4 + plain_len + GCM_TAG_LEN;

    /* Xoá key nhạy cảm khỏi stack */
    memset(eph_priv, 0, sizeof(eph_priv));
    memset(shared_x, 0, sizeof(shared_x));
    memset(k_enc,    0, sizeof(k_enc));

    return 0;
}

/* ========================================================
 * ecies_decrypt
 * ======================================================== */
int ecies_decrypt(const uint8_t  receiver_priv[32],
                  const uint8_t *in_buf,    size_t  in_len,
                  uint8_t       *plaintext, size_t *plain_len) {

    /* Kiểm tra độ dài tối thiểu */
    if (in_len < (size_t)ECIES_OVERHEAD) return -1;

    const uint8_t *p = in_buf;

    /* ---- Đọc gói tin ---- */
    const uint8_t *eph_pub    = p;       p += 65;
    const uint8_t *iv         = p;       p += 12;
    uint32_t       cipher_len = read_u32_be(p); p += 4;

    /* Kiểm tra độ dài nhất quán */
    if (in_len != 65 + 12 + 4 + cipher_len + GCM_TAG_LEN) return -1;

    const uint8_t *cipher_ptr = p;       p += cipher_len;
    const uint8_t *tag        = p;

    /* ---- Bước 1: ECDH → shared_x ---- */
    uint8_t shared_x[32];
    if (ecc_ecdh(receiver_priv, eph_pub, shared_x) != 0) {
        return -1;
    }

    /* ---- Bước 2: KDF → k_enc ---- */
    uint8_t k_enc[32], k_mac[32];
    ecies_derive_keys(shared_x, k_enc, k_mac);
    (void)k_mac;

    /* ---- Bước 3: GCM Decrypt + Verify tag ---- */
    int result = gcm_decrypt(k_enc, iv,
                             eph_pub, 65,         /* AAD = ephemeral public key */
                             cipher_ptr, cipher_len,
                             plaintext,
                             tag);

    /* Xoá key nhạy cảm */
    memset(shared_x, 0, sizeof(shared_x));
    memset(k_enc,    0, sizeof(k_enc));

    if (result != 0) return -1;  /* Authentication failed */

    *plain_len = cipher_len;
    return 0;
}
