

## Cấu Trúc Project

```
ECC Encrypt/
├── config.h               # Tham số Elliptic Curve secp256k1
├── elliptic_curve.h       # Point operations & Scalar multiplication
├── key_generation.h       # Sinh khóa (d, Q)
├── ecdh.h                # ECDH - Tính Shared Secret
├── kdf.h                 # KDF - Dẫn xuất AES Key
├── aes_gcm.h            # AES-256-GCM header
├── aes_gcm.cpp          # AES-256-GCM implementation
├── decryption.h         # Giải mã & Xác minh
├── main.cpp             # Chương trình Chính
├── Makefile             # Build với make
├── CMakeLists.txt       # Build với cmake
└── README.md            # File này
```

---

## Dependencies

### Required Libraries

1. **GMP (GNU Multiple Precision)**
   - Để tính toán bignum (số 256-bit)
   - Không phải crypto library

2. **OpenSSL**
   - Cho HMAC-SHA256 (KDF)
   - Cho AES-256-GCM encryption/decryption
   - Cho RAND_bytes() (sinh IV ngẫu nhiên)

### Installation

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get install libgmp-dev libssl-dev build-essential
```

#### macOS
```bash
brew install gmp openssl
```

#### Windows (MinGW/Visual Studio)
- GMP: https://gmplib.org/
- OpenSSL: https://slproweb.com/products/Win32OpenSSL.html

---

## Build & Run

### Using Makefile

```bash
# Build
make

# Run
make run

# Clean
make clean
```

### Using CMake

```bash
# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
cmake --build .

# Run
./ecc_encrypt
```

### Manual Compilation

```bash
g++ -std=c++11 -o ecc_encrypt main.cpp aes_gcm.cpp -lgmp -lssl -lcrypto
./ecc_encrypt
```

---

## Luồng Chương Trình

```
1. Key Generation
   └─ Alice: (d_A, Q_A)
   └─ Bob:   (d_B, Q_B)

2. ECDH (Trao đổi public key)
   └─ S = d_A * Q_B = d_B * Q_A  (Shared Secret)

3. KDF (Dẫn xuất khóa)
   └─ AES-Key = KDF(S_x)

4. AES-GCM Encryption
   └─ Ciphertext = AES-GCM(Plaintext, Key, IV)

5. Transmission
   └─ Gửi [Ciphertext, IV, Tag] qua kênh công khai

6. AES-GCM Decryption
   └─ Plaintext = AES-GCM(Ciphertext, Key, IV, Tag)

7. Verification
   └─ Plaintext_gốc == Plaintext_giải_mã ✓
```

---

## Chi Tiết Các Modules

### 1. `config.h` - Tham số Elliptic Curve

Định nghĩa secp256k1:
- `p`: Prime modulus
- `a, b`: Curve coefficients
- `Gx, Gy`: Base point G
- `n`: Order of G
- `h`: Cofactor

```cpp
mpz_class p = ECCConfig::p();
mpz_class n = ECCConfig::n();
EllipticCurvePoint G(ECCConfig::Gx(), ECCConfig::Gy());
```

### 2. `elliptic_curve.h` - ECC Operations

Clas `EllipticCurvePoint`:
- `x, y`: Tọa độ điểm
- `is_infinity`: Bool để lưu điểm vô cực

Class `EllipticCurve`:
- `mod_inverse(a, m)`: Tính a^-1 mod m (Extended GCD)
- `point_add(P, Q)`: Cộng hai điểm
- `point_multiply(k, P)`: Nhân vô hướng (Binary Method)
- `on_curve(P)`: Kiểm tra P có nằm trên curve

### 3. `key_generation.h` - Sinh Khóa

```cpp
struct KeyPair {
    mpz_class d;           // Private key (256-bit random)
    EllipticCurvePoint Q;  // Public key Q = d * G
};

auto keypair = KeyGeneration::generate_keypair();
```

### 4. `ecdh.h` - ECDH Protocol

```cpp
EllipticCurvePoint shared_secret = 
    ECDH::compute_shared_secret(private_key, public_key);
```

### 5. `kdf.h` - Key Derivation

Sử dụng HMAC-SHA256:

```cpp
unsigned char aes_key[32];
KDF::kdf_hmac_sha256(shared_secret.x, aes_key, 32);
```

### 6. `aes_gcm.h` / `aes_gcm.cpp` - AES-256-GCM

#### Lookup Tables:
- `sbox[256]`: AES S-box
- `inv_sbox[256]`: Inverse S-box
- `rcon[11]`: Round constant
- `gmul2[256], gmul3[256], ...`: Multiplication tables

#### Functions:
```cpp
void AES_GCM::encrypt(const uint8_t* plaintext, size_t len,
                     const uint8_t* key,
                     uint8_t* iv,
                     uint8_t* ciphertext,
                     uint8_t* tag);

bool AES_GCM::decrypt(const uint8_t* ciphertext, size_t len,
                     const uint8_t* key,
                     const uint8_t* iv,
                     const uint8_t* tag,
                     uint8_t* plaintext);
```

### 7. `decryption.h` - Decryption Module

```cpp
bool success = Decryption::decrypt_packet(
    ciphertext, len, iv, tag, key, plaintext
);
```

---

## Tính Chất Bảo Mật

| Component | Size | Security |
|-----------|------|----------|
| ECC Key | 256-bit | 128-bit |
| AES Key | 256-bit | 256-bit |
| GCM Tag | 128-bit | 128-bit |
| IV | 96-bit | 128-bit security level |

**Overall**: 128-bit security (limited by ECDLP assumption)

---

## Kết Quả Chạy (Sample Output)

```
============================================================
ECC Encrypt - End-to-End Encryption System (C++)
============================================================

[STEP 1] Key Generation - Sinh khóa cho Alice và Bob

============================================================
Alice - Key Generation
============================================================
Private Key (d): 0x...
Public Key (Q): (0x..., 0x...)
...

[STEP 2] ECDH - Tính Shared Secret
============================================================
ECDH (Elliptic Curve Diffie-Hellman)
============================================================
Shared Secret S = (..., ...)
...

[STEP 3] KDF - Dẫn xuất khóa AES từ Shared Secret
============================================================
KDF (Key Derivation Function)
============================================================
Derived Key (AES): ...
...

[STEP 4] AES-GCM Encryption - Alice mã hóa plaintext
============================================================
AES-256-GCM Encryption
============================================================
Plaintext: Hello Bob! This is a secret message from Alice.
Plaintext (hex): ...
Ciphertext (hex): ...
IV (hex): ...
Authentication Tag (hex): ...
...

[STEP 5] Transmission - Alice gửi ciphertext cho Bob
Alice gửi: [Ciphertext + IV + Tag] qua kênh công khai
Chỉ Bob (người có private key d_B) mới có thể giải mã

[STEP 6] AES-GCM Decryption - Bob giải mã
============================================================
AES-256-GCM Decryption
============================================================
Decrypted Plaintext: Hello Bob! This is a secret message from Alice.
...

✓ Decryption SUCCESSFUL - Plaintext matches!

============================================================
SUMMARY - Tóm tắt Quá trình
============================================================

✓ Key Generation:  Alice & Bob sinh cặp khóa ECC
✓ ECDH:           Tính Shared Secret dùng chung (d_A * Q_B = d_B * Q_A = S)
✓ KDF:            Dẫn xuất AES-256 key từ S_x
✓ AES-GCM Enc:    Alice mã hóa plaintext thành ciphertext
✓ Transmission:   Gửi [Ciphertext, IV, Tag] qua kênh công khai
✓ AES-GCM Dec:    Bob giải mã ciphertext bằng AES key
✓ Verification:   Plaintext gốc = Plaintext giải mã ✓

============================================================
ECC Encrypt Process Completed Successfully!
============================================================
```

---

## Compliance with Requirements

| Requirement | Status | Details |
|------------|--------|---------|
| No ECC library | ✓ | viết từ đầu: KeyGen, ECDH, KDF |
| Each block = 1 file | ✓ | 7 header files + 1 config |
| Main calls modules | ✓ | main.cpp orchestrates |
| Code from scratch | ✓ | Elliptic Curve math từ đầu |
| C/C++ Implementation | ✓ | C++ with GMP & OpenSSL |
| **Working** | ✓ | Full end-to-end encryption |

---

## Mở Rộng & Cải Tiến

Có thể thêm:
1. **Signature**: ECDSA để xác thực người gửi
2. **Compression**: Nén plaintext trước mã hóa
3. **Performance**: Hardware acceleration (AES-NI)
4. **Forward Secrecy**: Ephemeral keys per session
5. **Unit Tests**: Kiểm tra từng module

---

## Tài Liệu Tham Khảo

- SECP256K1: https://en.bitcoin.it/wiki/Secp256k1
- ECDH: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman
- AES-GCM: https://en.wikipedia.org/wiki/Galois/Counter_Mode
- GMP: https://gmplib.org/
- OpenSSL: https://www.openssl.org/

---

## License

Educational purpose - No warranty

---

**Date**: April 8, 2026  
**Status**: ✓ Complete  
**Language**: C++  
**Dependencies**: GMP, OpenSSL
