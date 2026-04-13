#ifndef ECDH_H
#define ECDH_H

#include "ecc/elliptic_curve.h"

class ECDH {
public:
    static Point compute_shared_secret(const EllipticCurve &ec,
                                       const mpz_class &priv_key,
                                       const Point &pub_key) {
        return ec.multiply(priv_key, pub_key);
    }
};

#endif /* ECDH_H */
