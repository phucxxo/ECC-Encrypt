# ECIES: Elliptic Curve Integrated Encryption Scheme 

## 📚 Giới thiệu


- **Lý thuyết đường cong elliptic (ECC)** và cách thực hiện nó
- **Trao đổi khóa Diffie-Hellman trên ECC (ECDH)**
- **Hàm dẫn xuất khóa (KDF)** dựa trên HKDF-SHA256
- **Mã hóa đối xứng (AES-256-GCM)** với xác thực
- **Quy trình mã hóa hoàn chỉnh** từ plaintext → ciphertext

---

## 🏗️ Kiến trúc Dự án

```
├── bignum.c/h          → Số học 256-bit không dấu
├── ecc.c/h             → Đường cong elliptic NIST P-256
├── sha256.c/h          → Hash SHA-256 + HMAC
├── hkdf.c/h            → HKDF (Key Derivation Function)
├── aes256.c/h          → AES-256 cipher
├── gcm.c/h             → AES-256-GCM (mã hóa + xác thực)
├── ecies.c/h           → ECIES (tổng hợp tất cả)
├── main.c              → Demo + unit tests
└── Makefile            → Build script
```

### 📋 Sơ đồ luồng dữ liệu ECIES

```
Alice (người gửi)                      Bob (người nhận)
        |                                    |
        |─→ [Generate Ephemeral Key] ←──────┐
        |                                    |
        |─→ [ECDH: r·Pub_Bob] ────────┐     │
        |                             │     │
        |  [Shared Secret]            │     │
        |       ↓                      │     │
        |  [HKDF: Derive Key]         │     │
        |       ↓                      │     │
        |  [AES-256-GCM Encrypt]      │     │
        |       ↓                      │     │
        |  [Packet: Eph ‖ IV ‖ Len ‖ Cipher ‖ Tag]
        |                             │     │
        └────────────────────────────→|─┐   │
                                       | │   │
                                       ↓ │   │
                                   [ECDH: d_Bob·Eph_Pub]
                                       | │   │
                                       ↓ │   │
                                   [Shared Secret]
                                       | │   │
                                       ↓ │   │
                                   [HKDF: Derive Key]
                                       | │   │
                                       ↓ │   │
                                   [Verify Tag & Decrypt]
                                       | │   │
                                       ↓ │   │
                                   [Plaintext] ✓
```

---

## � Sơ Đồ Tổng Quan Thuật Toán Mã Hóa ECIES Chi Tiết

![ECIES Encryption Flow Diagram](image.png)

### 🎯 Giải Thích Sơ Đồ Tổng Quan

Sơ đồ trên minh họa toàn bộ quy trình ECIES từ khởi tạo thông số đến khi giải mã thành công. Hãy xem chi tiết từng bước:

#### **1️⃣ Bước 1: Khởi tạo tham số miền (Domain Parameters)**

```
Đường cong: E(Fp): y² = x³ + ax + b mod p
Điểm sinh: G
Bậc: n
```

**Mô tả:**
- Tất cả các thành phố tham gia ECIES phải **thống nhất** sử dụng cùng tham số
- Với P-256, các tham số được định nghĩa bởi **NIST FIPS 186-4**
- `p` là số nguyên tố định nghĩa trường hữu hạn $\mathbb{F}_p$
- `a, b` là hệ số của phương trình đường cong
- `G` là điểm sinh (generator point)
- `n` là bậc của **G** (số điểm trên đường cong)

---

#### **2️⃣ Bước 2: Sinh Khóa (Key Generation)**

Chia làm 2 phía:

##### **Alice sinh khóa:**
```
d_A ∈ [1, n-1]    (ngẫu nhiên, 32 bytes) — private key (bí mật)
Q_A = d_A · G     (điểm trên đường cong) — public key (công khai)
```

**Quá trình:**
1. Alice chọn số ngẫu nhiên `d_A` trong khoảng [1, n-1]
2. Alice tính điểm `Q_A = d_A · G` bằng **scalar multiplication** (nhân vô hướng)
3. Alice công bố `Q_A`, giữ bí mật `d_A`

##### **Bob sinh khóa:**
```
d_B ∈ [1, n-1]    (ngẫu nhiên, 32 bytes) — private key (bí mật)
Q_B = d_B · G     (điểm trên đường cong) — public key (công khai)
```

**Quá trình tương tự như Alice**

---

#### **3️⃣ Bước 3: Trao Đổi Khóa ECDH (Elliptic Curve Diffie-Hellman)**

**Thuật toán ECDH:**

```
Mục tiêu: Alice và Bob tính được cùng 1 shared secret
         mà không ai khác biết được.

Alice tính:
  S = d_A · Q_B = d_A · (d_B · G)

Bob tính:
  S = d_B · Q_A = d_B · (d_A · G)

Do phép nhân trên elliptic curve là giao hoán:
  d_A · (d_B · G) = d_B · (d_A · G) = (d_A · d_B) · G

⟹ Alice và Bob đều có cùng điểm S
```

**Tại sao an toàn?**
- Kẻ tấn công biết `Q_A` và `Q_B` (công khai)
- Nhưng để tính `S` từ `Q_A, Q_B`, cần biết `d_A` hoặc `d_B`
- **ECDLP (Elliptic Curve Discrete Logarithm Problem):** Rất khó tìm `d_A` từ `Q_A`
- Với P-256 (256-bit), tương đương **RSA-4096** về độ khó

**Từ ECIES:**
```
Alice tính: S = d_A · Q_B
Bob tính:   S = d_B · Q_A
⟹ Cả hai có cùng S = (x_S, y_S)

Lấy toạ độ x: shared_x = x_S (32 bytes)
```

---

#### **4️⃣ Bước 4: Dẫn Xuất Khóa (KDF - Key Derivation Function)**

```
Input:  shared_x (32 bytes từ ECDH)
Output: k_enc (AES key), k_mac (optional)

k_enc, k_mac = HKDF-SHA256(shared_x)
```

**Tại sao cần KDF?**

1. **Expansion:** shared_x là 32 bytes, nhưng KDF có thể tạo ra bất kỳ độ dài nào
2. **Extraction:** Đảm bảo entropy từ shared_x được "trải đều" thành uniform random distribution
3. **Domain Separation:** Khác context string có thể tạo ra key khác nhau từ cùng shared_x

**Quy trình HKDF:**

```
HKDF = Extract-then-Expand

Extract phase:
  PRK = HMAC-SHA256(salt, shared_x)
  Salt = 0x00...00 (nếu không cung cấp)

Expand phase:
  T(0) = empty
  T(1) = HMAC-SHA256(PRK, T(0) ‖ "enc" ‖ 0x01)  → 32 bytes
  T(2) = HMAC-SHA256(PRK, T(1) ‖ "enc" ‖ 0x02)  → 32 bytes
  ...
  
  Output = T(1) ‖ T(2) ‖ ... (lấy đủ độ dài cần thiết)
```

---

#### **5️⃣ Bước 5: Mã Hóa Thông Điệp (Message Encryption)**

```
Input:  plaintext M, k_enc, IV/nonce
Output: ciphertext C, tag T

C = AES-256-GCM(k_enc, IV, M) ⟹ Mã hóa
T = GCM_TAG(k_enc, IV, M)     ⟹ Xác thực
```

**AES-256-GCM:**

- **Mã hóa:** Dùng CTR mode (Counter mode)
  ```
  Counter = E(k, IV ‖ counter++) ⊕ plaintext = ciphertext
  ```

- **Xác thực:** Dùng GHASH (Galois Hash)
  ```
  tag = GHASH(k_hash, IV, AD, ciphertext)
  AD = Additional Authenticated Data (ephemeral public key)
  ```

**Tại sao GCM?**

✅ **Confidentiality** (bảo mật nội dung bằng AES)  
✅ **Authenticity** (xác thực tag bằng GHASH)  
✅ **Integrity** (phát hiện tampering)  
✅ **Parallelizable** (có thể song song hóa)

---

#### **6️⃣ Bước 6: Đóng Gói Dữ Liệu (Packet Construction)**

```
Output packet = [Q_A_ephemeral] ‖ [IV] ‖ [Len] ‖ [C] ‖ [Tag]

Tổng kích thước = 65 + 12 + 4 + len(M) + 16 bytes
Overhead cố định = 97 bytes
```

**Chi tiết:**

| Phần | Kích thước | Mô tả | Ví dụ |
|------|-----------|-------|-------|
| Ephemeral PubKey | 65 bytes | Public key tạm thời của phía gửi | `04abcd...` |
| IV/Nonce | 12 bytes | Ngẫu nhiên, khác mỗi lần mã hóa | `cafebabe...` |
| Cipher Length | 4 bytes | Big-endian, độ dài plaintext | `000000DA` |
| Ciphertext | n bytes | Bản tin mã hóa (n = len(plaintext)) | `1a2b3c...` |
| Auth Tag | 16 bytes | GCM authentication tag | `9f8e7d6c...` |

---

#### **7️⃣ Bước 7: Truyền (Transmission)**

```
Alice ─→ [Encrypted Packet] ─→ Bob
         (không bí mật, có thể bị nghe lén)
         (nhưng không thể hiểu nội dung hoặc giả mạo)
```

---

#### **8️⃣ Bước 8: Giải Mã (Decryption)**

Bob nhận được gói tin và **thực hiện ngược lại:**

```
1. Đọc Q_A_ephemeral từ gói (65 bytes đầu)

2. ECDH lại:
   S = d_B · Q_A_ephemeral = (d_A · d_B) · G
   shared_x = x_S

3. KDF lại:
   k_enc, k_mac = HKDF-SHA256(shared_x)
   (Phải tạo lại chính xác key như Alice)

4. Giải mã + Xác thực:
   M = AES-256-GCM-Decrypt(k_enc, IV, ciphertext)
   Verify(tag) ← Nếu tag không khớp: REJECT (bản tin giả mạo!)
```

**Tại sao GCM xác thực được tampering?**

Nếu bất cứ byte nào trong ciphertext hoặc IV bị sửa:
- Tag được tính lại sẽ **khác hoàn toàn** so với tag gốc
- Phía nhận sẽ phát hiện và **từ chối** thông điệp
- Xác suất để giá mạo được tag đúng ~ 1/2¹²⁸ (không khả thi)

---

### 📈 Luồng Hoạt Động Toàn Bộ (End-to-End Flow)

```
┌─────────────────────────────────────────────────────────────┐
│                        ALICE (Sender)                        │
├─────────────────────────────────────────────────────────────┤
│ 1. Lấy public key Q_B của Bob (đã được cung cấp trước)     │
│ 2. Sinh ephemeral key pair (r, R=r·G)                      │
│    r = random 32 bytes                                      │
│    R = công khai lên trong gói tin                          │
│ 3. ECDH: S = r · Q_B                                        │
│    shared_x = x_S (32 bytes)                                │
│ 4. HKDF: k_enc, k_mac = Derive(shared_x)                   │
│ 5. AES-256-GCM Encrypt:                                     │
│    C, tag = Encrypt(k_enc, IV, plaintext)                   │
│    (IV được chọn ngẫu nhiên 12 bytes)                       │
│ 6. Đóng gói: [R ‖ IV ‖ Len ‖ C ‖ tag]                      │
│ 7. Gửi packet cho Bob                                       │
│ 8. Xóa sạch r, k_enc, k_mac khỏi memory                    │
└─────────────────────────────────────────────────────────────┘
                           ↓
                   (Gửi qua mạng)
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                         BOB (Receiver)                        │
├─────────────────────────────────────────────────────────────┤
│ 1. Nhận packet                                              │
│ 2. Đọc R từ 65 bytes đầu                                    │
│ 3. ECDH: S = d_B · R = d_B · (r · G) = r · (d_B · G)       │
│    shared_x = x_S (32 bytes, GIỐNG Alice)                   │
│ 4. HKDF: k_enc, k_mac = Derive(shared_x)                   │
│    (Tạo lại chính xác key như Alice)                        │
│ 5. AES-256-GCM Decrypt:                                     │
│    plaintext = Decrypt(k_enc, IV, ciphertext)              │
│    status = Verify(tag)                                     │
│    ─ Nếu status = -1 (tag sai): REJECT, báo lỗi           │
│    ─ Nếu status = 0 (tag đúng): Chấp nhận plaintext        │
│ 6. Xóa sạch k_enc, k_mac khỏi memory                       │
│ 7. Trả plaintext cho ứng dụng                              │
└─────────────────────────────────────────────────────────────┘
                           ✓ SUCCESS
```

---

### 🔒 Những Yếu Tố Bảo Mật Quan Trọng

| Bước | Yếu Tố | Tác Dụng |
|------|--------|---------|
| ECDH | Ephemeral key (r) | Mỗi phiên dùng key khác → Perfect Forward Secrecy |
| ECDH | Private key d_B bí mật | Không ai có thể tính S mà không có d_B |
| HKDF | Random salt | Đảm bảo uniform key distribution |
| AES-GCM | CTR mode | Mã hóa deterministic (với IV cố định) |
| GCM | GHASH tag | Xác thực + phát hiện tampering |
| GCM | IV phải unique | Nếu reuse IV → Mã bị phá! |

---

## �🔑 Các Module Chính

### 1️⃣ **bignum.c/h** — Số Học 256-bit

Cung cấp các phép toán trên số nguyên lớn 256-bit (8 từ 32-bit):

| Hàm | Mô tả |
|-----|-------|
| `bn_add()` | Phép cộng 2 số (A + B) |
| `bn_sub()` | Phép trừ (A - B) |
| `bn_mulmod()` | Phép nhân modulo: (A × B) mod M |
| `bn_invmod()` | Nghịch đảo modulo: A⁻¹ mod M |
| `bn_from_bytes()` | Nạp từ mảng 32 bytes big-endian |
| `bn_to_bytes()` | Xuất ra mảng 32 bytes big-endian |

**Ví dụ:**
```c
bn256 a, b, result;
bn_from_bytes(&a, bytes_32_a);
bn_from_bytes(&b, bytes_32_b);
bn_addmod(&result, &a, &b, &prime);  // result = (a + b) mod prime
```

---

### 2️⃣ **ecc.c/h** — Đường cong Elliptic P-256

Triển khai **NIST P-256** (secp256r1) dùng tọa độ **Jacobian** (X:Y:Z) để tối ưu hiệu năng.

#### Phương trình đường cong:
```
y² = x³ - 3x + b  (mod p)
```

#### Tham số (FIPS 186-4):
```
p (modulus)    = 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1
n (bậc của G)  = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G (điểm sinh)  = (0x6B17D1F2..., 0x4FE342E2...)
```

#### API Chính:

| Hàm | Mô tả |
|-----|-------|
| `ecc_keygen()` | Sinh cặp khóa (d, Q=d·G) từ 32 bytes ngẫu nhiên |
| `ecc_ecdh()` | Tính điểm chung: S = d·Pub_peer |
| `ec_scalar_mult()` | Nhân vô hướng (scalar multiplication): r = k·P |
| `ec_point_add_j()` | Cộng 2 điểm Jacobian |
| `ec_point_double_j()` | Nhân đôi điểm |

#### Tối ưu hóa:
- Dùng **tọa độ Jacobian** (X:Y:Z) thay vì affine (x,y) để tránh phép chia modular đắt giá (invmod)
- Chuyển về affine chỉ lúc cuối cùng
- Công thức cộng điểm: **add-2007-bl** (Bernstein-Lange)

**Ví dụ:**
```c
// Alice sinh key pair
uint8_t random_32[32] = {...};
uint8_t private_key[32];
uint8_t public_key[65];  // 04 || x || y
ecc_keygen(random_32, private_key, public_key);

// ECDH: tính shared secret
uint8_t bob_public[65];
uint8_t shared_x[32];    // x-coordinate của điểm chung
ecc_ecdh(private_key, bob_public, shared_x);
```

---

### 3️⃣ **sha256.c/h** — SHA-256 Hash

Triển khai **SHA-256** (FIPS 180-4):

| Hàm | Mô tả |
|-----|-------|
| `sha256_init()` | Khởi tạo context |
| `sha256_update()` | Xử lý dữ liệu (có thể gọi nhiều lần) |
| `sha256_final()` | Hoàn tất và lấy hash 32 bytes |
| `sha256()` | Hàm tiện lợi: hash toàn buffer |
| `hmac_sha256()` | HMAC-SHA256 |

**Ví dụ:**
```c
uint8_t digest[32];
sha256((const uint8_t*)"Hello", 5, digest);
// digest chứa hash SHA-256 của "Hello"
```

---

### 4️⃣ **hkdf.c/h** — HKDF (RFC 5869)

Hàm dẫn xuất khóa từ điểm chia sẻ ECC, gồm 2 bước:

1. **Extract**: `PRK = HMAC(salt, IKM)`
2. **Expand**: `OKM = T(1) ‖ T(2) ‖ ...` đến đủ độ dài

| Hàm | Mô tả |
|-----|-------|
| `hkdf_sha256()` | Dẫn xuất out_len bytes từ input key material |
| `ecies_derive_keys()` | Dẫn xuất k_enc (AES key) + k_mac từ shared_x |

**Ví dụ:**
```c
uint8_t shared_x[32];  // từ ECDH
uint8_t k_enc[32], k_mac[32];
ecies_derive_keys(shared_x, k_enc, k_mac);
// k_enc: AES-256 key
// k_mac: MAC key (không bắt buộc khi dùng GCM)
```

---

### 5️⃣ **aes256.c/h** — AES-256 Cipher

Triển khai **AES-256-ECB** (FIPS 197):

| Hàm | Mô tả |
|-----|-------|
| `aes256_init()` | Khởi tạo context, mở rộng key (14 rounds) |
| `aes256_encrypt_block()` | Mã hóa 1 block 16 bytes |
| `aes256_decrypt_block()` | Giải mã 1 block 16 bytes |

**Lưu ý:** 
- Chỉ cung cấp ECB mode (single block)
- Mode OF (GCM) được xử lý bởi module gcm.c

**Ví dụ:**
```c
uint8_t key[32], plaintext[16], ciphertext[16];
aes256_ctx ctx;
aes256_init(&ctx, key);
aes256_encrypt_block(&ctx, plaintext, ciphertext);
```

---

### 6️⃣ **gcm.c/h** — AES-256-GCM

Triển khai **AES-256-GCM** (NIST SP 800-38D):

| Tính năng | Giải thích |
|-----------|-----------|
| **Mã hóa** | Dùng CTR mode (Counter) với AES-256 |
| **Xác thực** | Dùng GHASH (Galois/Counter Mode hash) |
| **IV** | 12 bytes (96-bit), PHẢI khác nhau mỗi lần |
| **AAD** | Additional Authenticated Data (không mã hóa, nhưng được xác thực) |
| **Tag** | 16 bytes authentication tag |

| Hàm | Mô tả |
|-----|-------|
| `gcm_encrypt()` | Mã hóa + tạo tag |
| `gcm_decrypt()` | Giải mã + xác thực tag (trả về -1 nếu sai) |

**Ví dụ:**
```c
uint8_t key[32], iv[12], plaintext[100];
uint8_t ciphertext[100], tag[16];

// Mã hóa
gcm_encrypt(key, iv, NULL, 0, plaintext, 100, ciphertext, tag);

// Giải mã + xác thực
int ret = gcm_decrypt(key, iv, NULL, 0, ciphertext, 100, plaintext, tag);
if (ret == -1) {
    printf("ERROR: Tag không khớp (có giả mạo)\n");
}
```

#### Đặc tính bảo mật GCM:
✅ **Confidentiality** (Bảo mật nội dung): AES-256 CTR mode  
✅ **Authenticity** (Xác thực): GHASH verification  
✅ **Tamper Detection** (Phát hiện sửa đổi): Reject nếu tag không khớp

---

### 7️⃣ **ecies.c/h** — ECIES (Tổng Hợp)

Gộp tất cả các module lại thành một **Elliptic Curve Integrated Encryption Scheme**:

#### Cấu trúc gói tin mã hóa:

```
┌────────────────────────────────────────────┐
│ Ephemeral Public Key (65 bytes): 04||x||y  │
│ IV/Nonce (12 bytes)                        │
│ Cipher Length (4 bytes, big-endian)        │
│ Ciphertext (n bytes, n = len(plaintext))   │
│ Authentication Tag (16 bytes)              │
└────────────────────────────────────────────┘
Overhead cố định: 65 + 12 + 4 + 16 = 97 bytes
```

#### Luồng Mã hóa (Encrypt):

```
1. Sinh ephemeral key pair (r, R=r·G) từ random_key[32]
   └─ R là temporary public key cho phiên này

2. ECDH: shared_x = x-coordinate of (r · Pub_Receiver)
   └─ Chỉ dùng x-coordinate (32 bytes) làm KDF input

3. KDF: k_enc, k_mac = HKDF-SHA256(shared_x)
   └─ Dẫn xuất AES key từ ECC shared secret

4. AES-256-GCM Encrypt:
   └─ ciphertext, tag = Encrypt(k_enc, iv, plaintext)
   └─ AAD = ephemeral public key (đảm bảo R không bị thay đổi)

5. Đóng gói: R ‖ IV ‖ len ‖ ciphertext ‖ tag
```

#### Luồng Giải mã (Decrypt):

```
1. Đọc R từ gói tin (65 bytes đầu tiên)

2. ECDH: shared_x = x-coordinate of (d_Receiver · R)
   └─ Tạo lại shared secret từ R + private key

3. KDF: k_enc, k_mac = HKDF-SHA256(shared_x)
   └─ Dẫn xuất lại AES key

4. AES-256-GCM Decrypt:
   └─ plaintext = Decrypt(k_enc, iv, ciphertext, tag)
   └─ Nếu tag không khớp → REJECT (bản tin bị giả mạo)

5. Trả về plaintext + độ dài
```

| Hàm | Mô tả |
|-----|-------|
| `ecies_encrypt()` | Mã hóa plaintext bằng public key của người nhận |
| `ecies_decrypt()` | Giải mã gói tin bằng private key của người nhận |

**Ví dụ:**
```c
// Bob sinh key pair
uint8_t bob_priv[32], bob_pub[65];
ecc_keygen(random_bob, bob_priv, bob_pub);

// Alice mã hóa
const char *message = "Bí mật cho Bob";
size_t len = strlen(message);
uint8_t ciphertext[len + ECIES_OVERHEAD];
size_t cipher_len;

ecies_encrypt(bob_pub, random_eph_key, random_iv,
              (uint8_t*)message, len,
              ciphertext, &cipher_len);

// Bob giải mã
uint8_t plaintext[len];
size_t plain_len;
int ret = ecies_decrypt(bob_priv, ciphertext, cipher_len,
                        plaintext, &plain_len);

if (ret == 0) {
    printf("Plaintext: %s\n", (char*)plaintext);
} else {
    printf("LỖI: Bản tin bị giả mạo hoặc khóa sai!\n");
}
```

---

### 8️⃣ **main.c** — Demo & Unit Tests

Chương trình chính chạy các test:

1. **test_sha256()** — Kiểm tra SHA-256 với vector chuẩn FIPS
2. **test_aes256()** — Kiểm tra AES-256 ECB với vector NIST
3. **test_ecc_keygen()** — Sinh key pair ECC
4. **test_ecdh()** — Kiểm tra ECDH tạo shared secret giống nhau
5. **test_gcm()** — Kiểm tra mã hóa/giải mã GCM + detect tampering
6. **demo_ecies()** — Demo hoàn chỉnh: Alice → Bob

#### Kịch bản demo ECIES:
- Bob sinh cặp khóa (d_Bob, Pub_Bob)
- Alice chuẩn bị bản tin bí mật
- Alice mã hóa bằng Pub_Bob của Bob
- Bob giải mã bằng private key d_Bob
- **Test tamper detection**: Sửa 1 byte ciphertext → Bị từ chối
- **Test wrong key**: Dùng key sai → Bị từ chối

---

## 🚀 Biên Dịch & Chạy

### Yêu cầu:
- **Compiler**: GCC hoặc Clang
- **Hệ điều hành**: Linux, macOS, Windows (MinGW)
- **Standard**: C99 trở lên

### Build:
```bash
make
```

Lệnh này sẽ:
1. Biên dịch tất cả các file .c thành .o
2. Link thành executable `ecies_demo`

### Chạy:
```bash
./ecies_demo
```

### Clean:
```bash
make clean
```

### Output mẫu:
```
╔══════════════════════════════════════════╗
║    ECIES from scratch — C implementation  ║
║    Modules: bignum, ecc, sha256, hkdf,    ║
║             aes256, gcm, ecies             ║
╚══════════════════════════════════════════╝

========== Test SHA-256 ==========
SHA256("abc")         : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
Expected              : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

========== Test AES-256 ==========
AES256 plaintext      : 0011223344556677889900aabbccddddff
AES256 ciphertext     : 8ea2b7ca516745bfeafc49904b496089
...

========== Test ECDH ==========
Shared (Alice)        : 1a2b3c4d...
Shared (Bob)          : 1a2b3c4d...
ECDH match            : PASS

========================================
       ECIES Demo: Alice → Bob          
========================================

[Bob] Key pair:
  Private key: b0b123456789abcdef...
  Public key : 04abcdef...

[Alice] Plaintext (218 bytes):
  "Xin chao Bob! Day la ban tin bi mat duoc ma hoa bang ECIES..."

[Alice] Encrypted packet (315 bytes):
  Ephemeral pub key (65B): 04abcdef...
  IV (12B)               : cafebabe...
  Cipher len (4B)        : 000000da = 218 bytes
  Ciphertext (first 32B) : 1a2b3c4d...
  Auth tag (16B)         : 9f8e7d6c...

[Bob] Decrypt result: SUCCESS
[Bob] Plaintext (218 bytes):
  "Xin chao Bob! Day la ban tin bi mat duoc ma hoa bang ECIES..."

Message match         : PASS

--- Tamper detection test ---
Modified ciphertext: REJECTED (PASS)

--- Wrong private key ---
Wrong private key  : REJECTED (PASS)
```

---

## 🔐 Thảo luận An Toàn

### ✅ Điểm mạnh ECIES:

| Tính chất | Giải thích |
|-----------|-----------|
| **Ephemeral Key** | Mỗi lần mã hóa dùng key khác nhau → Perfect Forward Secrecy |
| **ECDH** | Shared secret được tính từ ECC, rất khó phá (256-bit ≈ RSA-4096) |
| **HKDF** | Dẫn xuất key từ shared secret thành uniform random |
| **GCM** | Xác thực ciphertext → Phát hiện tamper |
| **IV Random** | Mỗi lần mã hóa dùng IV khác → IND-CPA secure |

### ⚠️ Lưu ý bảo mật:

1. **Random Number Generation**:
   - ❌ **KHÔNG** dùng `rand()` trong ứng dụng thực tế!
   - ✅ **PHẢI** dùng `/dev/urandom` (Linux), `CryptGenRandom()` (Windows), `getrandom()` hoặc similar
   - Trong file main.c chỉ dùng giả ngẫu nhiên để demo có thể chạy lặp lại

2. **IV Reuse**:
   - ❌ **KHÔNG** dùng lại IV cho 2 lần mã hóa khác nhau
   - ⚠️ Nếu reuse IV + cùng key → Bản tin bị tiết lộ!

3. **Key Management**:
   - Private key phải bảo vệ tuyệt đối
   - Cleanup `memset()` để xoá key khỏi memory sau khi dùng

4. **Side-channel Attacks**:
   - Code này không được hardened chống timing attacks
   - Không thích hợp cho applications xử lý key siêu bí mật (ví dụ: thiết bị nhạy cảm)

### Các tấn công mà ECIES chống lại:

| Tấn công | Phòng chống |
|----------|------------|
| **Eavesdropping** | Ciphertext không tiết lộ plaintext |
| **Tampering** | GCM tag phát hiện sửa đổi |
| **Replay** | Không (cần thêm timestamp/nonce) |
| **Man-in-the-Middle** | Không (cần cơ chế xác thực khóa công khai) |
| **Chosen-Plaintext** | GCM là IND-CPA secure |

---

## 📖 Học thêm

### Tài liệu tham khảo:

1. **NIST FIPS 186-4** — Digital Signature Standard (includes P-256)
   - Tham số đường cong chính thức
   
2. **SEC 2: Recommended Elliptic Curve Domain Parameters**
   - secp256r1 (P-256) specifications

3. **NIST SP 800-38D** — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode
   - Định nghĩa GCM chính thức

4. **RFC 5869** — HKDF (HMAC-based Key Derivation Function)
   - Tiêu chuẩn HKDF

5. **FIPS 197** — Advanced Encryption Standard (AES)
   - Tiêu chuẩn AES

6. **FIPS 180-4** — Secure Hash Standard (SHA)
   - Tiêu chuẩn SHA-256

### Hyperelliptic EFD (Explicit-Formulas Database):
- https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
- Công thức cộng điểm Jacobian được dùng trong ecc.c

---

## 🎯 Ứng dụng Thực tế

ECIES được dùng trong:

- **TLS/SSL** (không phải ECIES chính xác, nhưng ECDH có)
- **Signal Protocol** (end-to-end encryption)
- **Blockchains** (Bitcoin, Ethereum key management)
- **IoT Security** (elliptic curve phù hợp với thiết bị nhỏ)
- **VPN & Secure Messaging**

---

## 🐛 Debug & Troubleshooting

### Compile errors?
- Đảm bảo C99 trở lên: `gcc -std=c99 ...`
- Kiểm tra include paths

### Output không khớp test vector?
- Kiểm tra endianness (big-endian vs little-endian)
- Xác minh tham số đường cong P-256 trong ecc.c

### Decrypt fail (tag mismatch)?
- Kiểm tra IV/nonce có khác nhau không
- Xác minh key derivation từ shared secret
- Ciartext có bị sửa đổi không

---

## 📝 Cấu trúc File Mã Nguồn

### bignum.c (< 500 lines)
- Phép toán số nguyên lớn 256-bit
- Modular arithmetic (add, sub, mul, inv)

### ecc.c (< 600 lines)
- Điểm affine & Jacobian
- Cộng, nhân đôi, nhân vô hướng
- Chuyển tọa độ

### sha256.c (< 400 lines)
- SHA-256 incremental
- HMAC implementation

### hkdf.c (< 150 lines)
- HKDF Extract-Expand
- ecies_derive_keys wrapper

### aes256.c (< 350 lines)
- AES key expansion (14 rounds)
- S-box, MixColumns, SubBytes, etc.

### gcm.c (< 350 lines)
- CTR mode encryption
- GHASH authentication
- Tag verification

### ecies.c (< 250 lines)
- Encrypt/Decrypt wrapper
- Packet packing/unpacking

### main.c (< 350 lines)
- Unit tests
- Full ECIES demo

