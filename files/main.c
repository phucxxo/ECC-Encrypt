/*
 * main.c — Chương trình chính minh hoạ ECIES
 *
 * Kịch bản: Alice muốn gửi bản tin bí mật cho Bob
 *
 * Chú ý quan trọng về random:
 *   Trong thực tế, PHẢI dùng OS random (getrandom(), /dev/urandom, CryptGenRandom).
 *   Ở đây dùng giả ngẫu nhiên cố định chỉ để demo có thể chạy được.
 *   KHÔNG dùng rand() trong ứng dụng thực tế!
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ecies.h"
#include "ecc.h"
#include "sha256.h"
#include "aes256.h"
#include "gcm.h"
#include "hkdf.h"
#include "bignum.h"

/* ========================================================
 * Hàm tiện ích in hex
 * ======================================================== */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%-20s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i+1) % 32 == 0 && i+1 < len) printf("\n%22s", "");
    }
    printf("\n");
}

/* ========================================================
 * "Ngẫu nhiên" giả cho demo — KHÔNG dùng trong thực tế!
 * Trong thực tế: đọc từ /dev/urandom hoặc dùng getrandom()
 * ======================================================== */
static void fake_random(uint8_t *buf, size_t len, uint32_t seed) {
    /* LCG đơn giản */
    for (size_t i = 0; i < len; i++) {
        seed = seed * 1664525u + 1013904223u;
        buf[i] = (uint8_t)(seed >> 16);
    }
    /* Đảm bảo byte cuối không zero (để d != 0) */
    if (buf[0] == 0) buf[0] = 0x42;
}

/* ========================================================
 * Test từng module riêng lẻ
 * ======================================================== */

static void test_sha256(void) {
    printf("\n========== Test SHA-256 ==========\n");
    /* Vector chuẩn FIPS 180-4 */
    const char *msg = "abc";
    uint8_t digest[32];
    sha256((const uint8_t*)msg, 3, digest);
    print_hex("SHA256(\"abc\")", digest, 32);
    printf("Expected          : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n");
}

static void test_aes256(void) {
    printf("\n========== Test AES-256 ==========\n");
    /* NIST test vector */
    uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    uint8_t plain[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    uint8_t cipher[16], decrypted[16];

    aes256_ctx ctx;
    aes256_init(&ctx, key);
    aes256_encrypt_block(&ctx, plain, cipher);
    aes256_decrypt_block(&ctx, cipher, decrypted);

    print_hex("AES256 plaintext ", plain,     16);
    print_hex("AES256 ciphertext", cipher,    16);
    print_hex("AES256 decrypted ", decrypted, 16);
    printf("Expected cipher   : 8ea2b7ca516745bfeafc49904b496089\n");
    printf("Decrypt match     : %s\n", memcmp(plain, decrypted, 16) == 0 ? "PASS" : "FAIL");
}

static void test_ecc_keygen(void) {
    printf("\n========== Test ECC Key Generation ==========\n");
    uint8_t rand_bytes[32];
    fake_random(rand_bytes, 32, 12345);

    uint8_t priv[32], pub[65];
    ecc_keygen(rand_bytes, priv, pub);

    print_hex("Private key", priv, 32);
    print_hex("Public key ", pub,  65);
    printf("Public key prefix : %s\n", pub[0] == 0x04 ? "04 (uncompressed) OK" : "ERROR");
}

static void test_ecdh(void) {
    printf("\n========== Test ECDH ==========\n");

    uint8_t rand_a[32], rand_b[32];
    fake_random(rand_a, 32, 0xAABBCCDD);
    fake_random(rand_b, 32, 0x11223344);

    uint8_t priv_a[32], pub_a[65];
    uint8_t priv_b[32], pub_b[65];
    ecc_keygen(rand_a, priv_a, pub_a);
    ecc_keygen(rand_b, priv_b, pub_b);

    uint8_t shared_a[32], shared_b[32];
    ecc_ecdh(priv_a, pub_b, shared_a);  /* Alice tính */
    ecc_ecdh(priv_b, pub_a, shared_b);  /* Bob tính   */

    print_hex("Shared (Alice)", shared_a, 32);
    print_hex("Shared (Bob)  ", shared_b, 32);
    printf("ECDH match        : %s\n",
           memcmp(shared_a, shared_b, 32) == 0 ? "PASS" : "FAIL");
}

static void test_gcm(void) {
    printf("\n========== Test AES-256-GCM ==========\n");
    uint8_t key[32]; fake_random(key, 32, 0xDEADBEEF);
    uint8_t iv[12];  fake_random(iv, 12,  0xCAFEBABE);

    const char *msg = "Hello, GCM world!";
    size_t msg_len  = strlen(msg);
    uint8_t cipher[64], plain2[64], tag[16];

    gcm_encrypt(key, iv, NULL, 0, (uint8_t*)msg, msg_len, cipher, tag);
    print_hex("GCM ciphertext", cipher, msg_len);
    print_hex("GCM tag       ", tag, 16);

    int ret = gcm_decrypt(key, iv, NULL, 0, cipher, msg_len, plain2, tag);
    plain2[msg_len] = '\0';
    printf("GCM decrypt       : %s\n", ret == 0 ? "PASS" : "FAIL (tag mismatch)");
    printf("GCM plaintext     : \"%s\"\n", (char*)plain2);

    /* Test tamper detection */
    cipher[0] ^= 0xFF;  /* Sửa 1 byte */
    ret = gcm_decrypt(key, iv, NULL, 0, cipher, msg_len, plain2, tag);
    printf("Tamper detection  : %s\n", ret == -1 ? "PASS (rejected)" : "FAIL");
}

/* ========================================================
 * Demo chính: Alice encrypt → Bob decrypt
 * ======================================================== */
static void demo_ecies(void) {
    printf("\n========================================\n");
    printf("       ECIES Demo: Alice → Bob          \n");
    printf("========================================\n");

    /* ---- Bước 1: Bob sinh key pair ---- */
    uint8_t rand_bob[32];
    fake_random(rand_bob, 32, 0xB0B12345);
    uint8_t bob_priv[32], bob_pub[65];
    ecc_keygen(rand_bob, bob_priv, bob_pub);

    printf("\n[Bob] Key pair:\n");
    print_hex("  Private key", bob_priv, 32);
    print_hex("  Public key ", bob_pub,  65);

    /* ---- Bước 2: Alice chuẩn bị bản tin ---- */
    const char *message =
        "Xin chao Bob! Day la ban tin bi mat duoc ma hoa bang ECIES.\n"
        "Cau truc: ECC key exchange + HKDF + AES-256-GCM.\n"
        "Viet tu scratch, khong dung thu vien crypto co san.";

    size_t msg_len = strlen(message);
    printf("\n[Alice] Plaintext (%zu bytes):\n  \"%s\"\n", msg_len, message);

    /* ---- Bước 3: Alice encrypt ---- */
    uint8_t rand_key[32], rand_iv[12];
    fake_random(rand_key, 32, 0xA11CE001);
    fake_random(rand_iv,  12, 0xA11CE002);

    size_t  out_len = msg_len + ECIES_OVERHEAD + 10;
    uint8_t *out_buf = malloc(out_len);
    if (!out_buf) { printf("malloc failed\n"); return; }

    int ret = ecies_encrypt(bob_pub, rand_key, rand_iv,
                            (const uint8_t*)message, msg_len,
                            out_buf, &out_len);

    if (ret != 0) { printf("[Alice] Encrypt FAILED\n"); free(out_buf); return; }

    printf("\n[Alice] Encrypted packet (%zu bytes):\n", out_len);
    printf("  Ephemeral pub key (65B): ");
    for (int i = 0; i < 65; i++) printf("%02x", out_buf[i]);
    printf("\n  IV (12B)               : ");
    for (int i = 65; i < 77; i++) printf("%02x", out_buf[i]);
    printf("\n  Cipher len (4B)        : ");
    for (int i = 77; i < 81; i++) printf("%02x", out_buf[i]);
    printf(" = %u bytes\n", (unsigned)msg_len);
    printf("  Ciphertext (first 32B) : ");
    for (int i = 81; i < 81+32 && i < (int)out_len-16; i++) printf("%02x", out_buf[i]);
    printf("\n  Auth tag (16B)         : ");
    for (int i = (int)out_len-16; i < (int)out_len; i++) printf("%02x", out_buf[i]);
    printf("\n");

    /* ---- Bước 4: Bob decrypt ---- */
    uint8_t *decrypted = malloc(msg_len + 1);
    size_t  dec_len;

    ret = ecies_decrypt(bob_priv, out_buf, out_len, decrypted, &dec_len);

    printf("\n[Bob] Decrypt result: %s\n", ret == 0 ? "SUCCESS" : "FAILED");
    if (ret == 0) {
        decrypted[dec_len] = '\0';
        printf("[Bob] Plaintext (%zu bytes):\n  \"%s\"\n", dec_len, decrypted);
        printf("\nMessage match     : %s\n",
               (dec_len == msg_len && memcmp(message, decrypted, msg_len) == 0)
               ? "PASS" : "FAIL");
    }

    /* ---- Bước 5: Test tamper detection ---- */
    printf("\n--- Tamper detection test ---\n");
    out_buf[100] ^= 0xFF;  /* Sửa 1 byte ciphertext */
    ret = ecies_decrypt(bob_priv, out_buf, out_len, decrypted, &dec_len);
    printf("Modified ciphertext: %s\n", ret == -1 ? "REJECTED (PASS)" : "FAIL");

    /* ---- Bước 6: Test wrong key ---- */
    uint8_t wrong_priv[32];
    fake_random(wrong_priv, 32, 0xDEADDEAD);
    out_buf[100] ^= 0xFF;  /* restore */
    ret = ecies_decrypt(wrong_priv, out_buf, out_len, decrypted, &dec_len);
    printf("Wrong private key  : %s\n", ret == -1 ? "REJECTED (PASS)" : "unexpected PASS");

    free(out_buf);
    free(decrypted);
}

/* ========================================================
 * main
 * ======================================================== */
int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║    ECIES from scratch — C implementation  ║\n");
    printf("║    Modules: bignum, ecc, sha256, hkdf,    ║\n");
    printf("║             aes256, gcm, ecies             ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    test_sha256();
    test_aes256();
    test_ecc_keygen();
    test_ecdh();
    test_gcm();
    demo_ecies();

    printf("\n========================================\n");
    printf("           All tests completed           \n");
    printf("========================================\n");
    return 0;
}
