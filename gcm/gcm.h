#ifndef GCM_H
#define GCM_H

/*
 * gcm.h — AES-256-GCM (Galois/Counter Mode)
 * Chuẩn: NIST SP 800-38D
 *
 * GCM = CTR mode mã hoá + GHASH xác thực
 *
 * Input:
 *   key   : 32 bytes AES-256 key
 *   iv    : 12 bytes (96-bit) — nonce, PHẢI khác nhau mỗi lần mã hoá!
 *   aad   : Additional Authenticated Data (không mã hoá, nhưng được xác thực)
 *   plain : Plaintext
 *
 * Output:
 *   cipher: Ciphertext (cùng độ dài plaintext)
 *   tag   : Authentication tag 16 bytes
 *
 * Decrypt + Verify:
 *   Nếu tag không khớp → trả về -1 (bản tin bị giả mạo)
 */

#include "aes256.h"
#include <stdint.h>
#include <stddef.h>

#define GCM_TAG_LEN  16
#define GCM_IV_LEN   12

/*
 * gcm_encrypt:
 *   plain[plain_len] → cipher[plain_len] + tag[16]
 * Trả về 0 nếu thành công
 */
int gcm_encrypt(const uint8_t key[AES_KEY_LEN],
                const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad,   size_t aad_len,
                const uint8_t *plain, size_t plain_len,
                uint8_t       *cipher,
                uint8_t        tag[GCM_TAG_LEN]);

/*
 * gcm_decrypt:
 *   cipher[cipher_len] + tag[16] → plain[cipher_len]
 * Trả về 0 nếu thành công, -1 nếu tag không khớp (tampered!)
 */
int gcm_decrypt(const uint8_t key[AES_KEY_LEN],
                const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad,    size_t aad_len,
                const uint8_t *cipher, size_t cipher_len,
                uint8_t       *plain,
                const uint8_t  tag[GCM_TAG_LEN]);

#endif /* GCM_H */
