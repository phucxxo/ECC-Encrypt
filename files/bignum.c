/*
 * bignum.c — Triển khai số nguyên lớn 256-bit
 *
 * Thuật toán nhân: schoolbook O(n²), 8x8 = 64 phép nhân 32-bit
 * Thuật toán mod: phép trừ lặp (phù hợp cho modular reduction sau nhân)
 * Thuật toán nghịch đảo: Extended Euclidean Algorithm (Binary GCD)
 */

#include "bignum.h"
#include <string.h>
#include <stdio.h>

/* ========================================================
 * Khởi tạo
 * ======================================================== */

void bn_zero(bn256 *r) {
    memset(r->w, 0, sizeof(r->w));
}

void bn_set_u32(bn256 *r, uint32_t val) {
    bn_zero(r);
    r->w[0] = val;
}

/* Nạp từ bytes big-endian: bytes[0] = most significant byte
 * → w[7] = bytes[0..3] (most significant word)
 * → w[0] = bytes[28..31] (least significant word) */
void bn_from_bytes(bn256 *r, const uint8_t bytes[32]) {
    for (int i = 0; i < 8; i++) {
        int base = (7 - i) * 4;   /* w[7] ← bytes[0], w[0] ← bytes[28] */
        r->w[i] = ((uint32_t)bytes[base]     << 24) |
                  ((uint32_t)bytes[base + 1] << 16) |
                  ((uint32_t)bytes[base + 2] <<  8) |
                  ((uint32_t)bytes[base + 3]);
    }
}

void bn_to_bytes(const bn256 *a, uint8_t bytes[32]) {
    for (int i = 0; i < 8; i++) {
        int base = (7 - i) * 4;
        bytes[base]     = (uint8_t)(a->w[i] >> 24);
        bytes[base + 1] = (uint8_t)(a->w[i] >> 16);
        bytes[base + 2] = (uint8_t)(a->w[i] >>  8);
        bytes[base + 3] = (uint8_t)(a->w[i]);
    }
}

void bn_copy(bn256 *dst, const bn256 *src) {
    memcpy(dst->w, src->w, sizeof(dst->w));
}

/* ========================================================
 * So sánh
 * ======================================================== */

int bn_is_zero(const bn256 *a) {
    for (int i = 0; i < BN_WORDS; i++)
        if (a->w[i]) return 0;
    return 1;
}

int bn_is_one(const bn256 *a) {
    if (a->w[0] != 1) return 0;
    for (int i = 1; i < BN_WORDS; i++)
        if (a->w[i]) return 0;
    return 1;
}

/* So sánh từ MSW xuống LSW */
int bn_cmp(const bn256 *a, const bn256 *b) {
    for (int i = BN_WORDS - 1; i >= 0; i--) {
        if (a->w[i] > b->w[i]) return  1;
        if (a->w[i] < b->w[i]) return -1;
    }
    return 0;
}

/* ========================================================
 * Số học cơ bản
 * ======================================================== */

uint32_t bn_add(bn256 *r, const bn256 *a, const bn256 *b) {
    uint64_t carry = 0;
    for (int i = 0; i < BN_WORDS; i++) {
        uint64_t sum = (uint64_t)a->w[i] + b->w[i] + carry;
        r->w[i] = (uint32_t)sum;
        carry   = sum >> 32;
    }
    return (uint32_t)carry;
}

uint32_t bn_sub(bn256 *r, const bn256 *a, const bn256 *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < BN_WORDS; i++) {
        uint64_t diff = (uint64_t)a->w[i] - b->w[i] - borrow;
        r->w[i] = (uint32_t)diff;
        borrow  = (diff >> 63) & 1;  /* MSB của diff 64-bit = borrow */
    }
    return (uint32_t)borrow;
}

uint32_t bn_shl1(bn256 *r, const bn256 *a) {
    uint32_t carry = 0;
    for (int i = 0; i < BN_WORDS; i++) {
        uint32_t next_carry = a->w[i] >> 31;
        r->w[i] = (a->w[i] << 1) | carry;
        carry = next_carry;
    }
    return carry;
}

int bn_bit(const bn256 *a, int i) {
    int word = i / 32;
    int bit  = i % 32;
    if (word >= BN_WORDS) return 0;
    return (a->w[word] >> bit) & 1;
}

/* ========================================================
 * Số học modular
 * ======================================================== */

void bn_reduce(bn256 *r, const bn256 *a, const bn256 *m) {
    bn_copy(r, a);
    while (bn_cmp(r, m) >= 0)
        bn_sub(r, r, m);
}

void bn_addmod(bn256 *r, const bn256 *a, const bn256 *b, const bn256 *m) {
    uint32_t carry = bn_add(r, a, b);
    /* Nếu có carry hoặc r >= m → trừ m */
    if (carry || bn_cmp(r, m) >= 0)
        bn_sub(r, r, m);
}

void bn_submod(bn256 *r, const bn256 *a, const bn256 *b, const bn256 *m) {
    uint32_t borrow = bn_sub(r, a, b);
    if (borrow)  /* a < b → cộng thêm m */
        bn_add(r, r, m);
}

/*
 * bn_mulmod: r = (a * b) mod m
 * Dùng thuật toán "shift-and-add" trên bignum:
 * Duyệt từng bit của b, tích luỹ (a << i) mod m khi bit i của b = 1
 * Độ phức tạp: O(256) phép addmod + O(256) phép shl + mod
 */
void bn_mulmod(bn256 *r, const bn256 *a, const bn256 *b, const bn256 *m) {
    bn256 temp, result;
    bn_zero(&result);
    bn_copy(&temp, a);
    bn_reduce(&temp, &temp, m);  /* đảm bảo temp < m */

    for (int i = 0; i < 256; i++) {
        if (bn_bit(b, i)) {
            bn_addmod(&result, &result, &temp, m);
        }
        /* temp = (temp * 2) mod m */
        uint32_t carry = bn_shl1(&temp, &temp);
        if (carry || bn_cmp(&temp, m) >= 0)
            bn_sub(&temp, &temp, m);
    }
    bn_copy(r, &result);
}

/*
 * bn_invmod: r = a^(-1) mod m
 * Thuật toán: Extended Binary GCD (Stein's algorithm variant)
 * Điều kiện: m là số nguyên tố (luôn tồn tại nghịch đảo khi a != 0)
 *
 * Dựa trên tính chất:
 *   nếu u·a ≡ 1 (mod m) thì u là nghịch đảo của a
 */
void bn_invmod(bn256 *r, const bn256 *a, const bn256 *m) {
    /* Dùng phương pháp: x = a^(m-2) mod m  (Fermat's little theorem)
     * Khi m là số nguyên tố: a^(m-1) ≡ 1 (mod m)
     * → a^(-1) = a^(m-2) mod m
     * Thuật toán: square-and-multiply (left-to-right) */
    bn256 base, exp, result, m_minus_2;

    bn_copy(&base, a);
    bn_reduce(&base, &base, m);

    /* exp = m - 2 */
    bn_set_u32(&m_minus_2, 2);
    bn_sub(&exp, m, &m_minus_2);

    /* result = 1 */
    bn_set_u32(&result, 1);

    /* Square-and-multiply: duyệt bit từ MSB xuống */
    for (int i = 255; i >= 0; i--) {
        /* result = result^2 mod m */
        bn_mulmod(&result, &result, &result, m);
        if (bn_bit(&exp, i)) {
            /* result = result * base mod m */
            bn_mulmod(&result, &result, &base, m);
        }
    }
    bn_copy(r, &result);
}

/* ========================================================
 * Debug
 * ======================================================== */

void bn_print_hex(const char *label, const bn256 *a) {
    printf("%s: ", label);
    for (int i = BN_WORDS - 1; i >= 0; i--)
        printf("%08x", a->w[i]);
    printf("\n");
}
