#ifndef ELLIPTIC_CURVE_H
#define ELLIPTIC_CURVE_H
#include "config.h"

struct Point {
    mpz_class x, y;
    bool is_infinity = false;
};

class EllipticCurve {
public:
    static Point add(Point P, Point Q) {
        if (P.is_infinity) return Q;
        if (Q.is_infinity) return P;
        mpz_class p = ECCConfig::p();
        mpz_class s;
        if (P.x == Q.x && P.y == Q.y) {
            s = (3 * P.x * P.x + ECCConfig::a()) * inverse(2 * P.y, p);
        } else {
            if (P.x == Q.x) return {0, 0, true};
            s = (Q.y - P.y) * inverse(Q.x - P.x, p);
        }
        s %= p;
        Point R;
        R.x = (s * s - P.x - Q.x) % p;
        R.y = (s * (P.x - R.x) - P.y) % p;
        if (R.x < 0) R.x += p; if (R.y < 0) R.y += p;
        return R;
    }

    static Point multiply(mpz_class k, Point P) {
        Point R; R.is_infinity = true;
        Point Q = P;
        while (k > 0) {
            if (k % 2 == 1) R = add(R, Q);
            Q = add(Q, Q);
            k /= 2;
        }
        return R;
    }

private:
    static mpz_class inverse(mpz_class a, mpz_class m) {
        mpz_class res;
        mpz_invert(res.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
        return res;
    }
};
#endif