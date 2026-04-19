# ECC Core

<p align="center">
  Minimal, readable Elliptic Curve arithmetic in modern C++.<br/>
  Focused on exactly two primitives: <b>point addition</b> and <b>scalar multiplication</b>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?logo=c%2B%2B&logoColor=white" alt="C++17"/>
  <img src="https://img.shields.io/badge/Dependency-None-2ea44f" alt="No external dependency"/>
  <img src="https://img.shields.io/badge/Status-Stable-1f6feb" alt="Stable"/>
  <img src="https://img.shields.io/badge/Scope-ECC%20Core-orange" alt="ECC core"/>
</p>

---

## Why This Project

This repository is intentionally reduced to the mathematical core of ECC:

- `point_add`: Add two points on an elliptic curve over a prime field.
- `scalar_multiply`: Compute `k * P` using the double-and-add algorithm.

No encryption pipeline, no hash/KDF/cipher modules, and no big-number library.
The implementation is small enough to study line-by-line.

---

## Features

- Clean separation between data model and arithmetic logic.
- Explicit handling of the point at infinity.
- Modular arithmetic helpers (`mod`, `mod_inverse`) for finite-field operations.
- Runtime checks for point validity on the curve.
- Interactive demo in `main.cpp` with clearly separated blocks.

---

## Project Structure

```text
ECC-Encrypt/
├── main.cpp                    # Demo program (addition + scalar multiplication)
├── Makefile                    # Build script (no external libraries)
└── src/
    └── ecc/
        ├── elliptic_curve.h    # Data structures + function declarations
        └── elliptic_curve.cpp  # ECC arithmetic implementation
```

---

## Mathematical Model

This demo uses short Weierstrass curves over a prime field:

`y^2 = x^3 + ax + b (mod p)`

Default demo parameters:

- `p = 97`
- `a = 2`
- `b = 3`
- `P = (3, 6)`
- `Q = (80, 10)`

Note: these values are intentionally small for readability and learning.
They are not production-secure parameters.

---

## Public API

Defined in [`src/ecc/elliptic_curve.h`](src/ecc/elliptic_curve.h):

- `std::int64_t mod(std::int64_t value, std::int64_t p);`
- `std::int64_t mod_inverse(std::int64_t value, std::int64_t p);`
- `bool is_on_curve(const Curve &curve, const Point &point);`
- `Point negate_point(const Curve &curve, const Point &point);`
- `Point point_add(const Curve &curve, const Point &p1, const Point &p2);`
- `Point scalar_multiply(const Curve &curve, std::int64_t k, const Point &point);`

---

## Build

Requirements:

- `g++` with C++17 support
- `make`

Commands:

```bash
make clean && make
```

Produced binary:

```bash
./ecc_core
```

---

## Demo Run

```text
===== ECC CORE (CHI GIU CONG + NHAN) =====
Duong cong dang dung: y^2 = x^3 + 2x + 3 (mod 97)

[BLOCK 1] CONG DIEM
P = (3, 6)
Q = (80, 10)
P + Q = (80, 87)

[BLOCK 2] NHAN VO HUONG
Nhap k de tinh k * P: 7
k * P = (80, 10)
```

---

## Design Notes

- This is a didactic ECC core, not a full cryptographic toolkit.
- Arithmetic uses `int64_t`, so overflow can occur for large parameters.
- For real-world ECC, move to validated big-integer arithmetic and constant-time code.

---

## Roadmap

- Add unit tests for edge cases (infinity, inverse points, invalid inputs).
- Add configurable curve/point input from CLI flags.
- Add optional verbose trace mode for each double-and-add step.

---

## Quick Start For Contributors

```bash
git clone <your-repo-url>
cd ECC-Encrypt
make clean && make
./ecc_core
```

If you change arithmetic logic, test with multiple `k` values including:

- `0`
- `1`
- negative `k`
- a multiple of point order (expect infinity)
