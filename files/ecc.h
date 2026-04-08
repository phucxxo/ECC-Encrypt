#ifndef ECC_H
#define ECC_H

/*
 * ecc.h — Đường cong elliptic NIST P-256 (secp256r1)
 *
 * Phương trình: y² = x³ - 3x + b  (mod p)
 * Tham số:
 *   p  = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
 *   a  = -3 (mod p)  = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
 *   b  = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
 *   Gx = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
 *   Gy = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
 *   n  = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 *
 * Dùng toạ độ Jacobian (X:Y:Z) để tránh phép tính nghịch đảo trong mỗi bước:
 *   Điểm affine (x,y) ↔ Jacobian (X,Y,Z) khi X=x·Z², Y=y·Z³
 */

#include "bignum.h"

/* ---- Điểm affine ---- */
typedef struct {
    bn256 x, y;
    int   infinity;   /* 1 = điểm vô cực (identity element) */
} ec_point;

/* ---- Điểm Jacobian (tọa độ chiếu) ---- */
typedef struct {
    bn256 X, Y, Z;
} ec_point_j;

/* ---- Tham số đường cong (export để các module khác dùng) ---- */
extern const bn256 EC_P;   /* modulus trường */
extern const bn256 EC_A;   /* hệ số a */
extern const bn256 EC_B;   /* hệ số b */
extern const bn256 EC_N;   /* bậc của điểm sinh G */
extern const ec_point EC_G; /* điểm sinh */

/* ========================================================
 * API chính
 * ======================================================== */

/*
 * Sinh cặp khoá
 * private_key: số ngẫu nhiên d ∈ [1, n-1]  (32 bytes big-endian)
 * public_key:  điểm Q = d·G trên đường cong  (65 bytes: 04 || x || y)
 *
 * Yêu cầu: random_32bytes là 32 bytes ngẫu nhiên thực sự
 */
void ecc_keygen(const uint8_t random_32bytes[32],
                uint8_t private_key[32],
                uint8_t public_key[65]);

/*
 * ECDH: tính điểm chung S = d · Q
 * private_key: 32 bytes big-endian
 * peer_public:  65 bytes (04 || x || y)
 * shared_x:    tọa độ x của S (32 bytes) — dùng làm input cho KDF
 * Trả về 0 nếu thành công, -1 nếu peer_public không hợp lệ
 */
int ecc_ecdh(const uint8_t private_key[32],
             const uint8_t peer_public[65],
             uint8_t shared_x[32]);

/* ========================================================
 * Hàm nội bộ (export để test)
 * ======================================================== */

/* Chuyển Jacobian → Affine */
void ec_j_to_affine(ec_point *r, const ec_point_j *p);

/* Chuyển Affine → Jacobian */
void ec_affine_to_j(ec_point_j *r, const ec_point *p);

/* Cộng hai điểm Jacobian: r = p + q */
void ec_point_add_j(ec_point_j *r, const ec_point_j *p, const ec_point_j *q);

/* Nhân đôi điểm Jacobian: r = 2*p */
void ec_point_double_j(ec_point_j *r, const ec_point_j *p);

/* Nhân vô hướng: r = k * p  (thuật toán double-and-add) */
void ec_scalar_mult(ec_point *r, const bn256 *k, const ec_point *p);

/* Kiểm tra điểm có nằm trên đường cong không */
int ec_point_on_curve(const ec_point *p);

#endif /* ECC_H */
