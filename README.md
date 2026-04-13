<a id="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![License][license-shield]][license-url]

<br />
<div align="center">
  <h3 align="center">ECC-Encrypt 🔐</h3>

  <p align="center">
    A Complete, From-Scratch Implementation of the ECIES Encryption Pipeline in C/C++
    <br />
    <a href="#about-the-project"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/phucxxo/ECC-Encrypt/issues">Report Bug</a>
    ·
    <a href="https://github.com/phucxxo/ECC-Encrypt/issues">Request Feature</a>
  </p>
</div>

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
        <li><a href="#encryption-pipeline">Encryption Pipeline</a></li>
        <li><a href="#architecture--structure">Architecture & Structure</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage--build">Usage & Build</a></li>
    <li><a href="#configuration">Configuration</a></li>
    <li><a href="#security-model">Security Model</a></li>
    <li><a href="#sample-output">Sample Output</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
  </ol>
</details>

## About The Project

**ECC-Encrypt** is a lightweight, educational Elliptic Curve Integrated Encryption Scheme (ECIES) pipeline implemented entirely from scratch in C and C++. It demonstrates the end-to-end process of hybrid encryption using Elliptic Curve Cryptography (ECC) without relying on large cryptographic libraries like OpenSSL for its core components.

The project breaks down the cryptographic workflow into purely modular, easy-to-understand components:
- **Elliptic Curve Diffie-Hellman (ECDH)** — Key Exchange on secp256k1
- **SHA-256** — Cryptographic hashing (FIPS 180-4)
- **HKDF-SHA256** — Key Derivation Function (RFC 5869)
- **AES-256** — Block Cipher (FIPS 197)
- **GCM** — Galois/Counter Mode for Authenticated Encryption (NIST SP 800-38D)

All algorithms are wrapped into a single `ECCEncrypt` C++ class, driven by a YAML configuration file — making it clean, configurable, and professional.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

* [![C++][C++-shield]][C++-url] C++17
* [![C][C-shield]][C-url] C11
* **GMP Library** — GNU Multiple Precision Arithmetic Library (for 256-bit big number math)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Encryption Pipeline

```text
Plaintext (user input)
    │
    ▼
┌──────────────────────────────────────────────────┐
│  BLOCK 1 — ECDH (Elliptic Curve Diffie-Hellman)  │
│  Curve: secp256k1                                 │
│  Alice: d_A × G → Q_A (public key)               │
│  Bob:   d_B × G → Q_B (public key)               │
│  Shared Secret: S = d_A × Q_B = d_B × Q_A        │
└──────────────────────────────────────────────────┘
    │  S.x (256-bit shared secret)
    ▼
┌──────────────────────────────────────────────────┐
│  BLOCK 2 — HKDF-SHA256 (Key Derivation)          │
│  Extract: PRK = HMAC-SHA256(salt, S.x)            │
│  Expand:  k_enc (32 bytes), k_mac (32 bytes)      │
└──────────────────────────────────────────────────┘
    │  k_enc (AES-256 key)
    ▼
┌──────────────────────────────────────────────────┐
│  BLOCK 3 — AES-256-GCM (Authenticated Encryption)│
│  CTR mode encryption + GHASH authentication       │
│  → Ciphertext + 128-bit Auth Tag                  │
└──────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────┐
│  BLOCK 4 — AES-256-GCM (Decryption & Verify)     │
│  Verify tag → Decrypt → Recovered Plaintext       │
└──────────────────────────────────────────────────┘
    │
    ▼
Recovered Plaintext ✅
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Architecture & Structure

```text
ECC-Encrypt/
├── src/                                # Source library — one directory per module
│   ├── sha256/                         # SHA-256 Hash (FIPS 180-4)
│   │   ├── sha256.h
│   │   └── sha256.c
│   ├── hkdf/                           # HKDF-SHA256 Key Derivation (RFC 5869)
│   │   ├── hkdf.h
│   │   └── hkdf.c
│   ├── aes256/                         # AES-256 Block Cipher (FIPS 197)
│   │   ├── aes256.h
│   │   └── aes256.c
│   ├── gcm/                            # AES-256-GCM Authenticated Encryption (NIST SP 800-38D)
│   │   ├── gcm.h
│   │   └── gcm.c
│   ├── ecc/                            # Elliptic Curve Math + ECDH Key Exchange
│   │   ├── elliptic_curve.h
│   │   └── ecdh.h
│   └── core/                           # Main class + Config parser
│       ├── ecc_encrypt.h               # ECCEncrypt class — wraps entire pipeline
│       └── config_parser.h             # Lightweight YAML config parser
├── configs/
│   └── configs.yaml                    # All configurable parameters
├── main.cpp                            # Minimal entry point
├── Makefile                            # Build system
└── README.md
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

### Prerequisites

The only external dependency is the **GMP library** for handling large integers used in elliptic curve calculations.

* **Linux (Ubuntu/Debian)**
  ```sh
  sudo apt-get update
  sudo apt-get install libgmp-dev build-essential
  ```
* **Arch Linux**
  ```sh
  sudo pacman -S gmp base-devel
  ```
* **macOS**
  ```sh
  brew install gmp
  ```

### Installation

1. Clone the repository
   ```sh
   git clone https://github.com/phucxxo/ECC-Encrypt.git
   ```
2. Navigate into the directory
   ```sh
   cd ECC-Encrypt
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage & Build

```sh
# Build the project
make clean && make

# Run — enter your plaintext when prompted
./ecc_encrypt

# Or pipe input directly
echo "Hello, World!" | ./ecc_encrypt
```

The program will print the full pipeline output showing **inputs and outputs of every block**: ECDH keys, HKDF derived keys, GCM ciphertext/tag, and the final decrypted result.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Configuration

All parameters are centralized in **`configs/configs.yaml`**:

```yaml
# Elliptic Curve (secp256k1)
ecc:
  p:  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
  a:  "0"
  b:  "7"
  Gx: "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
  Gy: "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
  n:  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

# Private Keys
keys:
  alice_private: "123456789123456789"
  bob_private:   "987654321987654321"

# HKDF Parameters
hkdf:
  salt:     "ECIES-P256-SHA256-v1"
  info_enc: "enc"
  info_mac: "mac"

# AES-256-GCM Parameters
gcm:
  iv:  "000102030405060708090a0b"
  aad: "ECC-Encrypt-v1"
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Security Model

| Component            | Specification              | Description                                 |
|----------------------|----------------------------|---------------------------------------------|
| **Key Generation**   | secp256k1 Curve            | 256-bit ECC Private/Public Keypair          |
| **Key Exchange**     | ECDH                       | Generates shared secret point on curve      |
| **Hashing**          | SHA-256 (FIPS 180-4)       | Merkle–Damgård construction, 256-bit digest |
| **Key Derivation**   | HKDF-SHA256 (RFC 5869)     | Extract-then-Expand, derives AES key        |
| **Encryption**       | AES-256-GCM (SP 800-38D)   | Authenticated encryption, 128-bit auth tag  |
| **Authentication**   | GHASH (GF(2¹²⁸))          | Constant-time tag verification              |

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Sample Output

```text
==========================================================
  ECC-ENCRYPT  PIPELINE
==========================================================

----------------------------------------------------------
  [BLOCK 1] INPUT
----------------------------------------------------------
  Plaintext (str) : "Hello, World!"
  Plaintext (hex) : 48656c6c6f2c20576f726c6421
  Size            : 13 bytes

----------------------------------------------------------
  [BLOCK 2] ECDH - Elliptic Curve Diffie-Hellman
----------------------------------------------------------
  Curve       : secp256k1
  Alice:
    Private key (d_A)   = 123456789123456789
    Public  key (Q_A).x = 32b0d10d...105ddcda
  Bob:
    Private key (d_B)   = 987654321987654321
    Public  key (Q_B).x = 3f82317a...7cb9f173
  Shared Secret Match   : YES ✅

----------------------------------------------------------
  [BLOCK 3] HKDF-SHA256 - Key Derivation
----------------------------------------------------------
  k_enc (AES-256 key)  = 6bca12fc...b9f372c2
  k_mac                = 6fe0523f...306c9834

----------------------------------------------------------
  [BLOCK 4] AES-256-GCM Encryption
----------------------------------------------------------
  Ciphertext           = e250201d...58d448
  Auth Tag             = 6b6210ef...e905f4

----------------------------------------------------------
  [BLOCK 5] AES-256-GCM Decryption & Verification
----------------------------------------------------------
  Decrypted (str)      = "Hello, World!"
  Verification         : PASSED ✅

==========================================================
  PIPELINE COMPLETE
==========================================================
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Roadmap

- [x] Implement Elliptic Curve operations on secp256k1
- [x] Implement ECDH Key Exchange
- [x] Implement SHA-256 (FIPS 180-4) + HMAC-SHA256
- [x] Implement HKDF-SHA256 (RFC 5869)
- [x] Implement AES-256 Block Cipher (FIPS 197)
- [x] Implement AES-256-GCM (NIST SP 800-38D)
- [x] Centralize into `ECCEncrypt` class with full pipeline
- [x] Add YAML configuration system
- [x] Add Makefile build system
- [ ] Add unit tests for each module
- [ ] Support other curves (P-256, P-384)
- [ ] Add CLI argument parsing

See the [open issues](https://github.com/phucxxo/ECC-Encrypt/issues) for a full list of proposed features and known issues.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

Distributed under the MIT License. Use for educational purposes.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

[contributors-shield]: https://img.shields.io/github/contributors/phucxxo/ECC-Encrypt.svg?style=for-the-badge
[contributors-url]: https://github.com/phucxxo/ECC-Encrypt/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/phucxxo/ECC-Encrypt.svg?style=for-the-badge
[forks-url]: https://github.com/phucxxo/ECC-Encrypt/network/members
[stars-shield]: https://img.shields.io/github/stars/phucxxo/ECC-Encrypt.svg?style=for-the-badge
[stars-url]: https://github.com/phucxxo/ECC-Encrypt/stargazers
[issues-shield]: https://img.shields.io/github/issues/phucxxo/ECC-Encrypt.svg?style=for-the-badge
[issues-url]: https://github.com/phucxxo/ECC-Encrypt/issues
[license-shield]: https://img.shields.io/github/license/phucxxo/ECC-Encrypt.svg?style=for-the-badge
[license-url]: https://github.com/phucxxo/ECC-Encrypt/blob/main/LICENSE
[C-shield]: https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white
[C-url]: https://en.cppreference.com/w/c
[C++-shield]: https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white
[C++-url]: https://isocpp.org/
