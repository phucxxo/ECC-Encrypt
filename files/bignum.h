#ifndef BIGNUM_H
#define BIGNUM_H

/*
 * bignum.h — Số nguyên lớn 256-bit không dấu
 * Biểu diễn: mảng 8 x uint32_t, words[0] = least significant
 *
 * Hỗ trợ: cộng, trừ, nhân, mod, so sánh, shift
 * Dùng cho: số học đường cong elliptic trên trường Fp (P-256)
 */

#include <stdint.h>
#include <stddef.h>

/* ---- Kiểu dữ liệu ---- */

#define BN_WORDS 8          /* 8 x 32-bit = 256 bit */

typedef struct {
    uint32_t w[BN_WORDS];  /* w[0] = least significant word */
} bn256;

/* ---- Khởi tạo ---- */

/* Đặt về 0 */
void bn_zero(bn256 *r);

/* Đặt bằng một số nguyên 32-bit nhỏ */
void bn_set_u32(bn256 *r, uint32_t val);

/* Nạp từ mảng bytes big-endian 32 bytes */
void bn_from_bytes(bn256 *r, const uint8_t bytes[32]);

/* Xuất ra mảng bytes big-endian 32 bytes */
void bn_to_bytes(const bn256 *a, uint8_t bytes[32]);

/* ---- So sánh ---- */

/* Trả về 1 nếu a == 0 */
int bn_is_zero(const bn256 *a);

/* Trả về 1 nếu a == 1 */
int bn_is_one(const bn256 *a);

/* Trả về <0, 0, >0 tương ứng a < b, a == b, a > b */
int bn_cmp(const bn256 *a, const bn256 *b);

/* ---- Số học cơ bản (không mod) ---- */

/* r = a + b, trả về carry (0 hoặc 1) */
uint32_t bn_add(bn256 *r, const bn256 *a, const bn256 *b);

/* r = a - b, trả về borrow (0 hoặc 1), giả sử a >= b */
uint32_t bn_sub(bn256 *r, const bn256 *a, const bn256 *b);

/* r = a << 1 (shift trái 1 bit), trả về carry */
uint32_t bn_shl1(bn256 *r, const bn256 *a);

/* Kiểm tra bit thứ i (i=0 là LSB) */
int bn_bit(const bn256 *a, int i);

/* ---- Số học modular ---- */

/* r = (a + b) mod m */
void bn_addmod(bn256 *r, const bn256 *a, const bn256 *b, const bn256 *m);

/* r = (a - b) mod m */
void bn_submod(bn256 *r, const bn256 *a, const bn256 *b, const bn256 *m);

/* r = (a * b) mod m  — dùng thuật toán nhân 512-bit rồi mod */
void bn_mulmod(bn256 *r, const bn256 *a, const bn256 *b, const bn256 *m);

/* r = a^(-1) mod m  — thuật toán Euclidean mở rộng */
void bn_invmod(bn256 *r, const bn256 *a, const bn256 *m);

/* r = a mod m  — giảm bằng phép trừ lặp (dùng khi a < 2m) */
void bn_reduce(bn256 *r, const bn256 *a, const bn256 *m);

/* ---- Copy ---- */
void bn_copy(bn256 *dst, const bn256 *src);

/* ---- Debug ---- */
void bn_print_hex(const char *label, const bn256 *a);

#endif /* BIGNUM_H */
