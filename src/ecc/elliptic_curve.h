#ifndef ELLIPTIC_CURVE_H
#define ELLIPTIC_CURVE_H

#include <gmpxx.h>

struct Point {
    mpz_class x, y;
    bool is_infinity = false;
};

class EllipticCurve {
public:
    EllipticCurve() : p_(0), a_(0) {}
    EllipticCurve(const mpz_class &p, const mpz_class &a) : p_(p), a_(a) {}

    Point add(Point P, Point Q) const {
        if (P.is_infinity) return Q;
        if (Q.is_infinity) return P;
        mpz_class s;
        if (P.x == Q.x && P.y == Q.y) {
            s = (3 * P.x * P.x + a_) * inverse(2 * P.y, p_);
        } else {
            if (P.x == Q.x) return {0, 0, true};
            s = (Q.y - P.y) * inverse(Q.x - P.x, p_);
        }
        s %= p_;
        Point R;
        R.x = (s * s - P.x - Q.x) % p_;
        R.y = (s * (P.x - R.x) - P.y) % p_;
        if (R.x < 0) R.x += p_;
        if (R.y < 0) R.y += p_;
        return R;
    }

    Point multiply(mpz_class k, Point P) const {
        Point R;
        R.is_infinity = true;
        Point Q = P;
        while (k > 0) {
            if (k % 2 == 1) R = add(R, Q);
            Q = add(Q, Q);
            k /= 2;
        }
        return R;
    }

private:
    mpz_class p_, a_;

    static mpz_class inverse(mpz_class a, mpz_class m) {
        mpz_class res;
        mpz_invert(res.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
        return res;
    }
};

#endif /* ELLIPTIC_CURVE_H */
