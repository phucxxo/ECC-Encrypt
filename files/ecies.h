#ifndef ECIES_H
#define ECIES_H

/*
 * ecies.h — ECIES: Elliptic Curve Integrated Encryption Scheme
 *
 * Ghép toàn bộ các module lại:
 *   ECC (ecc.c)  →  ECDH shared secret
 *   KDF (hkdf.c) →  Dẫn xuất AES key
 *   GCM (gcm.c)  →  Mã hoá + xác thực
 *
 * Cấu trúc gói tin mã hoá (ecies_packet):
 *   ┌─────────────────────────────────────────────────────┐
 *   │  ephemeral_pub [65 bytes] : 04 || x || y            │
 *   │  iv            [12 bytes] : AES-GCM nonce           │
 *   │  cipher_len    [4  bytes] : độ dài ciphertext       │
 *   │  ciphertext    [n  bytes] : bản mã (= len plaintext)│
 *   │  tag           [16 bytes] : GCM authentication tag  │
 *   └─────────────────────────────────────────────────────┘
 *   Tổng overhead cố định: 65 + 12 + 4 + 16 = 97 bytes
 *
 * Yêu cầu caller cung cấp:
 *   - 32 bytes ngẫu nhiên thực sự (ephemeral key)
 *   - 12 bytes ngẫu nhiên thực sự (IV/nonce)
 */

#include <stdint.h>
#include <stddef.h>

/* Kích thước overhead cố định */
#define ECIES_OVERHEAD  (65 + 12 + 4 + 16)  /* 97 bytes */

/*
 * ecies_encrypt:
 *
 * receiver_pub  : public key của người nhận (65 bytes: 04||x||y)
 * random_key    : 32 bytes ngẫu nhiên (cho ephemeral key pair)
 * random_iv     : 12 bytes ngẫu nhiên (cho AES-GCM IV)
 * plaintext     : bản tin gốc
 * plain_len     : độ dài bản tin
 * out_buf       : buffer nhận output (cần ít nhất plain_len + ECIES_OVERHEAD bytes)
 * out_len       : [out] độ dài thực tế của output
 *
 * Trả về 0 nếu thành công, -1 nếu lỗi
 */
int ecies_encrypt(const uint8_t  receiver_pub[65],
                  const uint8_t  random_key[32],
                  const uint8_t  random_iv[12],
                  const uint8_t *plaintext, size_t plain_len,
                  uint8_t       *out_buf,   size_t *out_len);

/*
 * ecies_decrypt:
 *
 * receiver_priv : private key của người nhận (32 bytes)
 * in_buf        : gói tin mã hoá (từ ecies_encrypt)
 * in_len        : độ dài gói tin
 * plaintext     : buffer nhận plaintext (cần ít nhất in_len - ECIES_OVERHEAD bytes)
 * plain_len     : [out] độ dài plaintext
 *
 * Trả về 0 nếu thành công, -1 nếu lỗi hoặc tag không hợp lệ
 */
int ecies_decrypt(const uint8_t  receiver_priv[32],
                  const uint8_t *in_buf,  size_t  in_len,
                  uint8_t       *plaintext, size_t *plain_len);

#endif /* ECIES_H */
