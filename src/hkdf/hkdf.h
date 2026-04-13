#ifndef HKDF_H
#define HKDF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t       *out,  size_t out_len);

void ecies_derive_keys(const uint8_t shared_x[32],
                       uint8_t k_enc[32],
                       uint8_t k_mac[32]);

#ifdef __cplusplus
}
#endif

#endif /* HKDF_H */
