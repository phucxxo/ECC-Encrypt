#include <iostream>
#include "ecdh.h"

int main() {
    Point G = {ECCConfig::Gx(), ECCConfig::Gy()};

    // Alice sinh khóa
    mpz_class d_Alice("123456789123456789"); 
    Point Q_Alice = EllipticCurve::multiply(d_Alice, G);

    // Bob sinh khóa
    mpz_class d_Bob("987654321987654321");
    Point Q_Bob = EllipticCurve::multiply(d_Bob, G);

    // Tính Shared Secret
    Point S_Alice = ECDH::compute_shared_secret(d_Alice, Q_Bob);
    Point S_Bob = ECDH::compute_shared_secret(d_Bob, Q_Alice);

    std::cout << "--- DEMO ECDH ---" << std::endl;
    std::cout << "Alice Shared Secret X: " << S_Alice.x.get_str(16) << std::endl;
    std::cout << "Bob Shared Secret X:   " << S_Bob.x.get_str(16) << std::endl;

    if (S_Alice.x == S_Bob.x) {
        std::cout << "\n==> THANH CONG! Hai ben co cung bi mat chung." << std::endl;
    }
    return 0;
}