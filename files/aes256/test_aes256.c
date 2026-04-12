/*
 * test_aes256.c — Test harness for AES-256 block cipher
 *
 * Tests:
 *   1. NIST FIPS 197 Appendix C.3 known-answer test vector
 *   2. Encrypt-then-decrypt roundtrip on a text block
 *   3. Multi-block text encryption (ECB, for demonstration only)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes256.h"

/* Print 'len' bytes as hex */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* Compare two buffers; return 0 if equal */
static int check(const char *name, const uint8_t *got, const uint8_t *want, size_t len) {
    if (memcmp(got, want, len) == 0) {
        printf("[PASS] %s\n", name);
        return 0;
    }
    printf("[FAIL] %s\n", name);
    print_hex("expected", want, len);
    print_hex("got     ", got, len);
    return 1;
}

/* --------------------------------------------------------
 * Test 1: NIST FIPS 197 Appendix C.3 — AES-256 ECB
 *   Key:       000102030405060708090a0b0c0d0e0f
 *              101112131415161718191a1b1c1d1e1f
 *   Plaintext: 00112233445566778899aabbccddeeff
 *   Ciphertext:8ea2b7ca516745bfeafc49904b496089
 * -------------------------------------------------------- */
static int test_nist_vector(void) {
    printf("=== Test 1: NIST FIPS 197 C.3 Known-Answer ===\n");

    const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    const uint8_t plaintext[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    const uint8_t expected_ct[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
        0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
    };

    aes256_ctx ctx;
    uint8_t ciphertext[16], decrypted[16];

    aes256_init(&ctx, key);
    aes256_encrypt_block(&ctx, plaintext, ciphertext);

    print_hex("key       ", key, 32);
    print_hex("plaintext ", plaintext, 16);
    print_hex("ciphertext", ciphertext, 16);

    int fails = 0;
    fails += check("encrypt matches NIST", ciphertext, expected_ct, 16);

    aes256_decrypt_block(&ctx, ciphertext, decrypted);
    print_hex("decrypted ", decrypted, 16);
    fails += check("decrypt recovers plaintext", decrypted, plaintext, 16);

    return fails;
}

/* --------------------------------------------------------
 * Test 2: Roundtrip — encrypt then decrypt a text block
 * -------------------------------------------------------- */
static int test_roundtrip_text(void) {
    printf("\n=== Test 2: Encrypt/Decrypt Roundtrip ===\n");

    /* 32-byte key (ASCII for simplicity) */
    const uint8_t key[32] = "my-secret-key-for-aes256-test!!";

    /* 16-byte plaintext block (exactly one AES block) */
    const uint8_t plaintext[16] = "Hello, AES-256!";  /* 15 chars + \0 = 16 bytes */

    aes256_ctx ctx;
    uint8_t ciphertext[16], decrypted[16];

    aes256_init(&ctx, key);
    aes256_encrypt_block(&ctx, plaintext, ciphertext);
    aes256_decrypt_block(&ctx, ciphertext, decrypted);

    printf("  plaintext : \"%.*s\"\n", 16, (const char *)plaintext);
    print_hex("ciphertext", ciphertext, 16);
    printf("  decrypted : \"%.*s\"\n", 16, (const char *)decrypted);

    return check("roundtrip text block", decrypted, plaintext, 16);
}

/* --------------------------------------------------------
 * Test 3: Multi-block text (ECB mode, for demonstration)
 *   Pads the input with zeros to a 16-byte boundary.
 * -------------------------------------------------------- */
static int test_multiblock(void) {
    printf("\n=== Test 3: Multi-Block ECB Text ===\n");

    const uint8_t key[32] = "another-32-byte-key-for-testing!";
    const char *message = "AES-256 works on 16-byte blocks. This tests multiple blocks!";
    size_t msg_len = strlen(message);

    /* Pad to next 16-byte boundary */
    size_t padded_len = ((msg_len + 15) / 16) * 16;
    uint8_t *padded    = calloc(padded_len, 1);
    uint8_t *encrypted = malloc(padded_len);
    uint8_t *decrypted = calloc(padded_len + 1, 1); /* +1 for display null */

    memcpy(padded, message, msg_len);

    aes256_ctx ctx;
    aes256_init(&ctx, key);

    /* Encrypt block by block */
    for (size_t i = 0; i < padded_len; i += 16)
        aes256_encrypt_block(&ctx, padded + i, encrypted + i);

    /* Decrypt block by block */
    for (size_t i = 0; i < padded_len; i += 16)
        aes256_decrypt_block(&ctx, encrypted + i, decrypted + i);

    printf("  original  : \"%s\"\n", message);
    print_hex("encrypted ", encrypted, padded_len);
    printf("  decrypted : \"%s\"\n", (const char *)decrypted);

    int fail = check("multi-block roundtrip", decrypted, padded, padded_len);

    free(padded);
    free(encrypted);
    free(decrypted);
    return fail;
}

/* -------------------------------------------------------- */
int main(void) {
    printf("AES-256 Test Suite\n");
    printf("==================\n\n");

    int total_fails = 0;
    total_fails += test_nist_vector();
    total_fails += test_roundtrip_text();
    total_fails += test_multiblock();

    printf("\n==================\n");
    if (total_fails == 0)
        printf("All tests PASSED.\n");
    else
        printf("%d test(s) FAILED.\n", total_fails);

    return total_fails;
}
