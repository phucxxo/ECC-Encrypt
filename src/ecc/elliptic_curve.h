#ifndef ELLIPTIC_CURVE_H
#define ELLIPTIC_CURVE_H

#include <cstdint>

struct Point {
    std::int64_t x;
    std::int64_t y;
    bool is_infinity;
};

struct Curve {
    std::int64_t p;
    std::int64_t a;
    std::int64_t b;
};

/* Chuan hoa ve [0, p-1] */
std::int64_t mod(std::int64_t value, std::int64_t p);

/* Tim nghich dao modulo bang Euclid mo rong */
std::int64_t mod_inverse(std::int64_t value, std::int64_t p);

/* Kiem tra diem nam tren duong cong: y^2 = x^3 + ax + b (mod p) */
bool is_on_curve(const Curve &curve, const Point &point);

/* Dao dau diem: (x, y) -> (x, -y mod p) */
Point negate_point(const Curve &curve, const Point &point);

/* Cong hai diem tren duong cong */
Point point_add(const Curve &curve, const Point &p1, const Point &p2);

/* Nhan vo huong: k * P, dung double-and-add */
Point scalar_multiply(const Curve &curve, std::int64_t k, const Point &point);

#endif
