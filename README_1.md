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
    A Complete, From-Scratch Implementation of the ECIES Encrypted Pipeline in C/C++!
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
        <li><a href="#architecture-and-structure">Architecture & Structure</a></li>
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
    <li><a href="#security-model">Security Model</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
  </ol>
</details>

## About The Project

**ECC-Encrypt** is a lightweight, educational Elliptic Curve Integrated Encryption Scheme (ECIES) pipeline implemented almost entirely from scratch in C and C++. It demonstrates the end-to-end process of public-key encryption using Elliptic Curve Cryptography (ECC) without relying on huge cryptographic libraries like OpenSSL for its core symmetric components.

The project breaks down the cryptographic workflow into purely modular, easy-to-understand components: 
- Elliptic Curve Diffie-Hellman (ECDH) Key Exchange
- Hash-based Key Derivation Function (HKDF)
- Advanced Encryption Standard (AES-256)
- Galois/Counter Mode (GCM) for Authenticated Encryption

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

* [![C++][C++-shield]][C++-url]
* [![C][C-shield]][C-url]
* **GMP Library** (GNU Multiple Precision Arithmetic Library - Used exclusively for 256-bit Big Number mathematics)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Architecture and Structure

The codebase is professionally separated into modular directories corresponding to the ECIES workflow:

```text
ECC-Encrypt/
├── ecdh/         # Elliptic Curve Operations, secp256k1 params, ECDH Shared Secret
├── hkdf/         # HKDF implementation (RFC 5869) & SHA-256 hashing
├── aes256/       # AES-256 block cipher implementation (FIPS 197)
├── gcm/          # Galois/Counter Mode (GCM) for authenticated encryption
└── README.md     # Project documentation
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

The only external dependency required is the **GMP library** for handling large integers (big numbers) used in elliptic curve calculations. You no longer need OpenSSL.

* **Linux (Ubuntu/Debian)**
  ```sh
  sudo apt-get update
  sudo apt-get install libgmp-dev build-essential
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

You can compile the modules and run the demonstration by linking the C and C++ sources together. Here is an example of compiling the ECDH demonstration:

```sh
# Compile the ECDH main application
g++ -std=c++11 -o ecdh_demo ecdh/main.cpp -lgmp

# Run the program
./ecdh_demo
```

*(Note: Ensure you include other `.c` files such as `hkdf/hkdf.c`, `hkdf/sha256.c`, `aes256/aes256.c`, and `gcm/gcm.c` in your build command as you integrate the full compiling pipeline.)*

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Security Model

| Component            | Specification              | Security Description                        |
|----------------------|----------------------------|---------------------------------------------|
| **Key Generation**   | secp256k1 Curve            | 256-bit ECC Private/Public Keypair          |
| **Key Exchange**     | ECDH                       | Generates robust shared secret point        |
| **Key Derivation**   | HKDF-SHA256                | Derives secure AES keys from shared secret  |
| **Encryption**       | AES-256-GCM                | Authenticated encryption (128-bit security) |

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Roadmap

- [x] Implement ECDH and Big Num Operations
- [x] Implement AES-256 Core
- [x] Implement AES-GCM Mode
- [x] Implement HKDF & SHA-256
- [ ] Centralize `main.cpp` for the complete ECIES pipeline
- [ ] Add Makefile / CMakeLists.txt for easy building

See the [open issues](https://github.com/phucxxo/ECC-Encrypt/issues) for a full list of proposed features (and known issues).

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