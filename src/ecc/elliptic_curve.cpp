#include "elliptic_curve.h"

std::int64_t mod(std::int64_t value, std::int64_t p) {
    std::int64_t result = value % p;
    if (result < 0) {
        result += p;
    }
    return result;
}

std::int64_t mod_inverse(std::int64_t value, std::int64_t p) {
    std::int64_t t = 0;
    std::int64_t new_t = 1;
    std::int64_t r = p;
    std::int64_t new_r = mod(value, p);

    while (new_r != 0) {
        std::int64_t quotient = r / new_r;

        std::int64_t next_t = t - quotient * new_t;
        t = new_t;
        new_t = next_t;

        std::int64_t next_r = r - quotient * new_r;
        r = new_r;
        new_r = next_r;
    }

    if (r != 1) {
        return 0;
    }

    return mod(t, p);
}

bool is_on_curve(const Curve &curve, const Point &point) {
    if (point.is_infinity) {
        return true;
    }

    std::int64_t left = mod(point.y * point.y, curve.p);
    std::int64_t right = mod(point.x * point.x * point.x + curve.a * point.x + curve.b, curve.p);
    return left == right;
}

Point negate_point(const Curve &curve, const Point &point) {
    if (point.is_infinity) {
        return point;
    }
    return {point.x, mod(-point.y, curve.p), false};
}

Point point_add(const Curve &curve, const Point &p1, const Point &p2) {
    if (p1.is_infinity) {
        return p2;
    }
    if (p2.is_infinity) {
        return p1;
    }

    if (p1.x == p2.x && mod(p1.y + p2.y, curve.p) == 0) {
        return {0, 0, true};
    }

    std::int64_t slope = 0;

    if (p1.x == p2.x && p1.y == p2.y) {
        std::int64_t denominator = mod(2 * p1.y, curve.p);
        std::int64_t inv = mod_inverse(denominator, curve.p);
        if (inv == 0) {
            return {0, 0, true};
        }
        slope = mod((3 * p1.x * p1.x + curve.a) * inv, curve.p);
    } else {
        std::int64_t denominator = mod(p2.x - p1.x, curve.p);
        std::int64_t inv = mod_inverse(denominator, curve.p);
        if (inv == 0) {
            return {0, 0, true};
        }
        slope = mod((p2.y - p1.y) * inv, curve.p);
    }

    std::int64_t rx = mod(slope * slope - p1.x - p2.x, curve.p);
    std::int64_t ry = mod(slope * (p1.x - rx) - p1.y, curve.p);

    return {rx, ry, false};
}

Point scalar_multiply(const Curve &curve, std::int64_t k, const Point &point) {
    if (k == 0 || point.is_infinity) {
        return {0, 0, true};
    }

    if (k < 0) {
        return scalar_multiply(curve, -k, negate_point(curve, point));
    }

    Point result = {0, 0, true};
    Point addend = point;

    while (k > 0) {
        if (k & 1LL) {
            result = point_add(curve, result, addend);
        }
        addend = point_add(curve, addend, addend);
        k >>= 1;
    }

    return result;
}
