#ifndef ECDH_H
#define ECDH_H
#include "elliptic_curve.h"

class ECDH {
public:
    static Point compute_shared_secret(mpz_class priv_key, Point pub_key) {
        // Shared Secret = Khóa bí mật của mình * Khóa công khai đối phương
        return EllipticCurve::multiply(priv_key, pub_key);
    }
};
#endif