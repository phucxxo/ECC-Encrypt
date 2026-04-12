#ifndef HKDF_H
#define HKDF_H

/*
 * hkdf.h — HKDF (HMAC-based Key Derivation Function)
 * Chuẩn: RFC 5869
 *
 * Gồm 2 bước:
 *   1. Extract: PRK = HMAC(salt, IKM)
 *   2. Expand:  OKM = T(1) ‖ T(2) ‖ ... đến đủ độ dài
 *
 * Dùng trong ECIES để biến shared_secret (điểm ECC)
 * thành các key đối xứng đồng đều.
 */

#include <stdint.h>
#include <stddef.h>

/*
 * hkdf_sha256: dẫn xuất out_len bytes từ input key material
 *
 * ikm       : input key material (vd: shared_secret.x từ ECDH)
 * ikm_len   : độ dài ikm
 * salt      : salt ngẫu nhiên hoặc hằng số (NULL → dùng 0x00...00)
 * salt_len  : độ dài salt
 * info      : context string (vd: "aes-key", "hmac-key")
 * info_len  : độ dài info
 * out       : buffer nhận key output
 * out_len   : số bytes cần dẫn xuất (tối đa 255 * 32 = 8160 bytes)
 */
void hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t       *out,  size_t out_len);

/*
 * ecies_derive_keys: hàm tiện lợi cho ECIES
 * Từ shared_x (32 bytes từ ECDH), dẫn xuất:
 *   - k_enc: AES-256 key (32 bytes)
 *   - k_mac: không cần riêng khi dùng GCM (GCM tự có authentication)
 *            nhưng vẫn export để test / dùng với HMAC
 */
void ecies_derive_keys(const uint8_t shared_x[32],
                       uint8_t k_enc[32],
                       uint8_t k_mac[32]);

#endif /* HKDF_H */