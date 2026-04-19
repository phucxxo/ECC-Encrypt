#include <iostream>

#include "src/ecc/elliptic_curve.h"

void print_point(const char *label, const Point &point) {
    if (point.is_infinity) {
        std::cout << label << " = O (point at infinity)\n";
        return;
    }
    std::cout << label << " = (" << point.x << ", " << point.y << ")\n";
}

void print_curve_info(const Curve &curve) {
    std::cout << "Duong cong dang dung: y^2 = x^3 + "
              << curve.a << "x + " << curve.b
              << " (mod " << curve.p << ")\n";
}

void run_point_addition_block(const Curve &curve, const Point &p, const Point &q) {
    std::cout << "\n[BLOCK 1] CONG DIEM\n";
    print_point("P", p);
    print_point("Q", q);

    Point sum = point_add(curve, p, q);
    print_point("P + Q", sum);
}

void run_scalar_multiplication_block(const Curve &curve, const Point &p) {
    std::cout << "\n[BLOCK 2] NHAN VO HUONG\n";

    long long k = 0;
    std::cout << "Nhap k de tinh k * P: ";
    if (!(std::cin >> k)) {
        std::cout << "Gia tri k khong hop le.\n";
        return;
    }

    Point product = scalar_multiply(curve, k, p);
    print_point("k * P", product);
}

int main() {
    Curve curve = {97, 2, 3};
    Point p = {3, 6, false};
    Point q = {80, 10, false};

    std::cout << "===== ECC CORE (CHI GIU CONG + NHAN) =====\n";
    print_curve_info(curve);

    if (!is_on_curve(curve, p) || !is_on_curve(curve, q)) {
        std::cout << "P hoac Q khong nam tren duong cong.\n";
        return 1;
    }

    run_point_addition_block(curve, p, q);
    run_scalar_multiplication_block(curve, p);

    return 0;
}
