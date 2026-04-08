/*
 * ecc.c — Triển khai đường cong elliptic NIST P-256
 *
 * Dùng tọa độ Jacobian để tối ưu hiệu năng:
 *   - Phép cộng điểm affine cần 1 lần nghịch đảo (đắt)
 *   - Tọa độ Jacobian hoãn phép nghịch đảo đến cuối cùng
 *
 * Tài liệu tham khảo công thức:
 *   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
 */

#include "ecc.h"
#include <string.h>
#include <stdio.h>

/* ========================================================
 * Tham số P-256 (NIST FIPS 186-4)
 * ======================================================== */

/* p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
const bn256 EC_P = {{ 
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
}};

/* a = p - 3 */
const bn256 EC_A = {{
    0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
}};

/* b = random constant */
const bn256 EC_B = {{
    0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
    0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8
}};

/* n = bậc của G */
const bn256 EC_N = {{
    0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
}};

/* Điểm sinh G */
const ec_point EC_G = {
    .x = {{ 0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
            0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2 }},
    .y = {{ 0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
            0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2 }},
    .infinity = 0
};

/* ========================================================
 * Chuyển đổi tọa độ
 * ======================================================== */

void ec_affine_to_j(ec_point_j *r, const ec_point *p) {
    bn_copy(&r->X, &p->x);
    bn_copy(&r->Y, &p->y);
    bn_set_u32(&r->Z, 1);
}

/* Chuyển Jacobian (X:Y:Z) → Affine (x,y)
 * x = X / Z^2,  y = Y / Z^3  (mod p)
 * Cần 2 phép mulmod + 1 invmod */
void ec_j_to_affine(ec_point *r, const ec_point_j *p) {
    /* Kiểm tra điểm vô cực: Z = 0 */
    if (bn_is_zero(&p->Z)) {
        r->infinity = 1;
        bn_zero(&r->x);
        bn_zero(&r->y);
        return;
    }

    bn256 z_inv, z2, z3;

    /* z_inv = Z^(-1) mod p */
    bn_invmod(&z_inv, &p->Z, &EC_P);

    /* z2 = z_inv^2 mod p */
    bn_mulmod(&z2, &z_inv, &z_inv, &EC_P);

    /* z3 = z_inv^3 mod p */
    bn_mulmod(&z3, &z2, &z_inv, &EC_P);

    /* x = X * z2 mod p */
    bn_mulmod(&r->x, &p->X, &z2, &EC_P);

    /* y = Y * z3 mod p */
    bn_mulmod(&r->y, &p->Y, &z3, &EC_P);

    r->infinity = 0;
}

/* ========================================================
 * Phép cộng điểm Jacobian
 * Công thức: add-2007-bl (Bernstein-Lange)
 * r = p + q  (p ≠ q, không phải điểm vô cực)
 *
 * Input:  (X1:Y1:Z1), (X2:Y2:Z2)
 * Output: (X3:Y3:Z3)
 *
 * U1 = X1*Z2^2,  U2 = X2*Z1^2
 * S1 = Y1*Z2^3,  S2 = Y2*Z1^3
 * H  = U2 - U1,  R  = S2 - S1
 * X3 = R^2 - H^3 - 2*U1*H^2
 * Y3 = R*(U1*H^2 - X3) - S1*H^3
 * Z3 = H*Z1*Z2
 * ======================================================== */
void ec_point_add_j(ec_point_j *r, const ec_point_j *p, const ec_point_j *q) {
    /* Xử lý điểm vô cực (Z=0) */
    if (bn_is_zero(&p->Z)) { *r = *q; return; }
    if (bn_is_zero(&q->Z)) { *r = *p; return; }

    const bn256 *m = &EC_P;
    bn256 Z1sq, Z2sq, U1, U2, Z1cu, Z2cu, S1, S2;
    bn256 H, R, H2, H3, U1H2, tmp;

    /* Z1^2, Z2^2 */
    bn_mulmod(&Z1sq, &p->Z, &p->Z, m);
    bn_mulmod(&Z2sq, &q->Z, &q->Z, m);

    /* U1 = X1*Z2^2,  U2 = X2*Z1^2 */
    bn_mulmod(&U1, &p->X, &Z2sq, m);
    bn_mulmod(&U2, &q->X, &Z1sq, m);

    /* Z1^3, Z2^3 */
    bn_mulmod(&Z1cu, &Z1sq, &p->Z, m);
    bn_mulmod(&Z2cu, &Z2sq, &q->Z, m);

    /* S1 = Y1*Z2^3,  S2 = Y2*Z1^3 */
    bn_mulmod(&S1, &p->Y, &Z2cu, m);
    bn_mulmod(&S2, &q->Y, &Z1cu, m);

    /* H = U2 - U1,  R = S2 - S1 */
    bn_submod(&H, &U2, &U1, m);
    bn_submod(&R, &S2, &S1, m);

    /* Nếu H = 0: cùng điểm → dùng doubling */
    if (bn_is_zero(&H)) {
        if (bn_is_zero(&R)) {
            /* p == q → double */
            ec_point_double_j(r, p);
        } else {
            /* p == -q → điểm vô cực */
            bn_zero(&r->X); bn_set_u32(&r->Y, 1); bn_zero(&r->Z);
        }
        return;
    }

    /* H^2, H^3 */
    bn_mulmod(&H2, &H, &H, m);
    bn_mulmod(&H3, &H2, &H, m);

    /* U1*H^2 */
    bn_mulmod(&U1H2, &U1, &H2, m);

    /* X3 = R^2 - H^3 - 2*U1*H^2  (mod p) */
    bn_mulmod(&r->X, &R, &R, m);           /* R^2 */
    bn_submod(&r->X, &r->X, &H3, m);      /* - H^3 */
    bn_submod(&r->X, &r->X, &U1H2, m);    /* - U1H2 */
    bn_submod(&r->X, &r->X, &U1H2, m);    /* - U1H2 lần 2 = -2*U1H2 */

    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    bn_submod(&tmp, &U1H2, &r->X, m);
    bn_mulmod(&r->Y, &R, &tmp, m);
    bn_mulmod(&tmp, &S1, &H3, m);
    bn_submod(&r->Y, &r->Y, &tmp, m);

    /* Z3 = H * Z1 * Z2 */
    bn_mulmod(&r->Z, &H, &p->Z, m);
    bn_mulmod(&r->Z, &r->Z, &q->Z, m);
}

/* ========================================================
 * Nhân đôi điểm Jacobian
 * Công thức: dbl-2007-bl
 *
 * Với a = -3 trên P-256, có thể tối ưu:
 *   M = 3*(X-Z^2)*(X+Z^2)  (thay vì M = 3*X^2 + a*Z^4)
 *
 * S = 4*X*Y^2
 * M = 3*X^2 + a*Z^4  (với a=-3: M = 3*(X^2 - Z^4))
 * X' = M^2 - 2*S
 * Y' = M*(S - X') - 8*Y^4
 * Z' = 2*Y*Z
 * ======================================================== */
void ec_point_double_j(ec_point_j *r, const ec_point_j *p) {
    if (bn_is_zero(&p->Z)) { *r = *p; return; }

    const bn256 *m = &EC_P;
    bn256 Y2, S, M, Z2, X2, Y4, tmp;

    /* Y^2 */
    bn_mulmod(&Y2, &p->Y, &p->Y, m);

    /* S = 4 * X * Y^2 */
    bn_mulmod(&S, &p->X, &Y2, m);
    bn_addmod(&S, &S, &S, m);   /* *2 */
    bn_addmod(&S, &S, &S, m);   /* *2 = *4 */

    /* X^2 */
    bn_mulmod(&X2, &p->X, &p->X, m);

    /* Z^2 */
    bn_mulmod(&Z2, &p->Z, &p->Z, m);

    /* Z^4 */
    bn256 Z4;
    bn_mulmod(&Z4, &Z2, &Z2, m);

    /* M = 3*X^2 + a*Z^4, với a = EC_A
     * Vì EC_A = p-3 ≡ -3 (mod p):
     * M = 3*X^2 - 3*Z^4 = 3*(X^2 - Z^4) */
    bn_submod(&M, &X2, &Z4, m);
    bn_addmod(&tmp, &M, &M, m);
    bn_addmod(&M, &M, &tmp, m);  /* M = 3*(X^2 - Z^4) */

    /* X' = M^2 - 2*S */
    bn_mulmod(&r->X, &M, &M, m);
    bn_submod(&r->X, &r->X, &S, m);
    bn_submod(&r->X, &r->X, &S, m);

    /* Y' = M*(S - X') - 8*Y^4 */
    bn_submod(&tmp, &S, &r->X, m);
    bn_mulmod(&r->Y, &M, &tmp, m);
    bn_mulmod(&Y4, &Y2, &Y2, m);
    /* 8*Y4 */
    bn_addmod(&Y4, &Y4, &Y4, m);
    bn_addmod(&Y4, &Y4, &Y4, m);
    bn_addmod(&Y4, &Y4, &Y4, m);
    bn_submod(&r->Y, &r->Y, &Y4, m);

    /* Z' = 2*Y*Z */
    bn_mulmod(&r->Z, &p->Y, &p->Z, m);
    bn_addmod(&r->Z, &r->Z, &r->Z, m);
}

/* ========================================================
 * Nhân vô hướng: r = k * p
 * Thuật toán: Double-and-Add (left-to-right, 256 bước)
 *
 * An toàn cơ bản: duyệt đủ 256 bit kể cả 0 để tránh timing attack
 * đơn giản. Không phải constant-time hoàn toàn (bài học).
 * ======================================================== */
void ec_scalar_mult(ec_point *r, const bn256 *k, const ec_point *p) {
    ec_point_j result_j, p_j, tmp_j;

    /* result = điểm vô cực (Z=0) */
    bn_zero(&result_j.X);
    bn_set_u32(&result_j.Y, 1);
    bn_zero(&result_j.Z);

    /* p_j = p trong tọa độ Jacobian */
    ec_affine_to_j(&p_j, p);

    /* Duyệt từ bit 255 xuống bit 0 */
    for (int i = 255; i >= 0; i--) {
        /* result = 2 * result */
        ec_point_double_j(&tmp_j, &result_j);
        result_j = tmp_j;

        /* Nếu bit i của k = 1: result = result + p */
        if (bn_bit(k, i)) {
            ec_point_add_j(&tmp_j, &result_j, &p_j);
            result_j = tmp_j;
        }
    }

    /* Chuyển về affine */
    ec_j_to_affine(r, &result_j);
}

/* ========================================================
 * Kiểm tra điểm có trên đường cong
 * Điều kiện: y^2 ≡ x^3 + ax + b (mod p)
 * ======================================================== */
int ec_point_on_curve(const ec_point *p) {
    if (p->infinity) return 1;

    bn256 lhs, rhs, x2, x3, ax;
    const bn256 *m = &EC_P;

    /* lhs = y^2 mod p */
    bn_mulmod(&lhs, &p->y, &p->y, m);

    /* x^2 */
    bn_mulmod(&x2, &p->x, &p->x, m);
    /* x^3 */
    bn_mulmod(&x3, &x2, &p->x, m);
    /* ax = a * x mod p */
    bn_mulmod(&ax, &EC_A, &p->x, m);
    /* rhs = x^3 + ax + b mod p */
    bn_addmod(&rhs, &x3, &ax, m);
    bn_addmod(&rhs, &rhs, &EC_B, m);

    return bn_cmp(&lhs, &rhs) == 0;
}

/* ========================================================
 * API công khai: ecc_keygen
 * ======================================================== */
void ecc_keygen(const uint8_t random_32bytes[32],
                uint8_t private_key[32],
                uint8_t public_key[65]) {
    bn256 d;
    ec_point Q;

    /* d = random mod (n-1) + 1, đảm bảo d ∈ [1, n-1] */
    bn_from_bytes(&d, random_32bytes);
    bn_reduce(&d, &d, &EC_N);
    if (bn_is_zero(&d)) bn_set_u32(&d, 1);  /* cực kỳ hiếm */

    /* Q = d * G */
    ec_scalar_mult(&Q, &d, &EC_G);

    /* Xuất private key */
    bn_to_bytes(&d, private_key);

    /* Xuất public key dạng uncompressed: 04 || x || y */
    public_key[0] = 0x04;
    bn_to_bytes(&Q.x, public_key + 1);
    bn_to_bytes(&Q.y, public_key + 33);
}

/* ========================================================
 * API công khai: ecc_ecdh
 * ======================================================== */
int ecc_ecdh(const uint8_t private_key[32],
             const uint8_t peer_public[65],
             uint8_t shared_x[32]) {
    /* Kiểm tra tiền tố */
    if (peer_public[0] != 0x04) return -1;

    bn256 d;
    ec_point Q, S;

    bn_from_bytes(&d, private_key);

    bn_from_bytes(&Q.x, peer_public + 1);
    bn_from_bytes(&Q.y, peer_public + 33);
    Q.infinity = 0;

    /* Kiểm tra Q có trên đường cong không */
    if (!ec_point_on_curve(&Q)) return -1;

    /* S = d * Q */
    ec_scalar_mult(&S, &d, &Q);

    if (S.infinity) return -1;

    /* Lấy tọa độ x */
    bn_to_bytes(&S.x, shared_x);
    return 0;
}
