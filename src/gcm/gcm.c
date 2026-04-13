/*
 * gcm.c — AES-256-GCM (NIST SP 800-38D)
 */

#include "gcm.h"
#include <string.h>
#include <stdint.h>

static void ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    uint8_t v[16], z[16];
    memcpy(v, h, 16);
    memset(z, 0, 16);

    for (int i = 0; i < 16; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            if ((x[i] >> bit) & 1) {
                for (int k = 0; k < 16; k++) z[k] ^= v[k];
            }
            uint8_t carry = v[15] & 1;
            for (int k = 15; k > 0; k--)
                v[k] = (v[k] >> 1) | (v[k-1] << 7);
            v[0] >>= 1;
            if (carry) v[0] ^= 0xe1;
        }
    }
    memcpy(x, z, 16);
}

static void ghash_update_block(uint8_t state[16], const uint8_t block[16],
                                const uint8_t H[16]) {
    for (int i = 0; i < 16; i++) state[i] ^= block[i];
    ghash_mul(state, H);
}

static void ghash_data(uint8_t state[16], const uint8_t *data, size_t len,
                       const uint8_t H[16]) {
    while (len >= 16) {
        ghash_update_block(state, data, H);
        data += 16;
        len  -= 16;
    }
    if (len > 0) {
        uint8_t pad_block[16];
        memset(pad_block, 0, 16);
        memcpy(pad_block, data, len);
        ghash_update_block(state, pad_block, H);
    }
}

static void ctr_inc(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++ctr[i]) break;
    }
}

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
    if (len > 0) {
        aes256_encrypt_block(aes_ctx, ctr, keystream);
        for (size_t i = 0; i < len; i++) out[i] = in[i] ^ keystream[i];
    }
}

int gcm_encrypt(const uint8_t key[AES_KEY_LEN],
                const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad,   size_t aad_len,
                const uint8_t *plain, size_t plain_len,
                uint8_t       *cipher,
                uint8_t        tag[GCM_TAG_LEN]) {
    aes256_ctx aes_ctx;
    aes256_init(&aes_ctx, key);

    uint8_t H[16];
    memset(H, 0, 16);
    aes256_encrypt_block(&aes_ctx, H, H);

    uint8_t J0[16];
    memcpy(J0, iv, GCM_IV_LEN);
    J0[12] = 0x00; J0[13] = 0x00; J0[14] = 0x00; J0[15] = 0x01;

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    ctr_inc(ctr);

    ctr_crypt(&aes_ctx, ctr, plain, cipher, plain_len);

    uint8_t ghash_state[16];
    memset(ghash_state, 0, 16);
    ghash_data(ghash_state, aad, aad_len, H);
    ghash_data(ghash_state, cipher, plain_len, H);

    uint8_t len_block[16];
    uint64_t aad_bits   = (uint64_t)aad_len   * 8;
    uint64_t plain_bits = (uint64_t)plain_len  * 8;
    for (int i = 7; i >= 0; i--) {
        len_block[i]     = (uint8_t)(aad_bits   >> ((7-i)*8));
        len_block[8 + i] = (uint8_t)(plain_bits >> ((7-i)*8));
    }
    ghash_update_block(ghash_state, len_block, H);

    uint8_t enc_j0[16];
    aes256_encrypt_block(&aes_ctx, J0, enc_j0);
    for (int i = 0; i < GCM_TAG_LEN; i++)
        tag[i] = ghash_state[i] ^ enc_j0[i];

    return 0;
}

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

    uint8_t diff = 0;
    for (int i = 0; i < GCM_TAG_LEN; i++)
        diff |= (expected_tag[i] ^ tag[i]);
    if (diff != 0) return -1;

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    ctr_inc(ctr);
    ctr_crypt(&aes_ctx, ctr, cipher, plain, cipher_len);

    return 0;
}
