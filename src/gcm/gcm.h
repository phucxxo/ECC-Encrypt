#ifndef GCM_H
#define GCM_H

#include "aes256/aes256.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GCM_TAG_LEN  16
#define GCM_IV_LEN   12

int gcm_encrypt(const uint8_t key[AES_KEY_LEN],
                const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad,   size_t aad_len,
                const uint8_t *plain, size_t plain_len,
                uint8_t       *cipher,
                uint8_t        tag[GCM_TAG_LEN]);

int gcm_decrypt(const uint8_t key[AES_KEY_LEN],
                const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad,    size_t aad_len,
                const uint8_t *cipher, size_t cipher_len,
                uint8_t       *plain,
                const uint8_t  tag[GCM_TAG_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* GCM_H */
