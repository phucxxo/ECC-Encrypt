#ifndef ECC_ENCRYPT_H
#define ECC_ENCRYPT_H

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <gmpxx.h>

#include "sha256/sha256.h"
#include "hkdf/hkdf.h"
#include "aes256/aes256.h"
#include "gcm/gcm.h"

#include "ecc/elliptic_curve.h"
#include "ecc/ecdh.h"
#include "core/config_parser.h"

class ECCEncrypt {
public:
    explicit ECCEncrypt(const std::string &config_path) {
        cfg_ = ConfigParser::parse(config_path);
        mpz_class p(cfg_["ecc.p"]);
        mpz_class a(cfg_["ecc.a"]);
        ec_ = EllipticCurve(p, a);
    }

    void run(const std::string &plaintext) {
        separator("ECC-ENCRYPT  PIPELINE");

        /* ───────── BLOCK 1: INPUT ───────── */
        header("BLOCK 1", "INPUT");
        std::cout << "  Plaintext (str) : \"" << plaintext << "\"\n";
        std::cout << "  Plaintext (hex) : " << to_hex((const uint8_t *)plaintext.data(), plaintext.size()) << "\n";
        std::cout << "  Size            : " << plaintext.size() << " bytes\n\n";

        /* ───────── BLOCK 2: ECDH ───────── */
        header("BLOCK 2", "ECDH - Elliptic Curve Diffie-Hellman");
        mpz_class Gx(cfg_["ecc.Gx"]);
        mpz_class Gy(cfg_["ecc.Gy"]);
        Point G = {Gx, Gy};

        std::cout << "  Curve       : secp256k1\n";
        std::cout << "  Generator G :\n";
        std::cout << "    Gx = " << Gx.get_str(16) << "\n";
        std::cout << "    Gy = " << Gy.get_str(16) << "\n\n";

        mpz_class d_alice(cfg_["keys.alice_private"]);
        mpz_class d_bob  (cfg_["keys.bob_private"]);

        Point Q_alice = ec_.multiply(d_alice, G);
        Point Q_bob   = ec_.multiply(d_bob,   G);

        std::cout << "  Alice:\n";
        std::cout << "    Private key (d_A)  = " << d_alice.get_str(10) << "\n";
        std::cout << "    Public  key (Q_A).x = " << Q_alice.x.get_str(16) << "\n";
        std::cout << "    Public  key (Q_A).y = " << Q_alice.y.get_str(16) << "\n\n";

        std::cout << "  Bob:\n";
        std::cout << "    Private key (d_B)  = " << d_bob.get_str(10) << "\n";
        std::cout << "    Public  key (Q_B).x = " << Q_bob.x.get_str(16) << "\n";
        std::cout << "    Public  key (Q_B).y = " << Q_bob.y.get_str(16) << "\n\n";

        Point S_alice = ECDH::compute_shared_secret(ec_, d_alice, Q_bob);
        Point S_bob   = ECDH::compute_shared_secret(ec_, d_bob,   Q_alice);

        std::cout << "  Shared Secret (Alice) S = d_A x Q_B:\n";
        std::cout << "    S.x = " << S_alice.x.get_str(16) << "\n";
        std::cout << "    S.y = " << S_alice.y.get_str(16) << "\n";
        std::cout << "  Shared Secret (Bob)   S = d_B x Q_A:\n";
        std::cout << "    S.x = " << S_bob.x.get_str(16) << "\n";
        std::cout << "    S.y = " << S_bob.y.get_str(16) << "\n";
        std::cout << "  => Match: " << (S_alice.x == S_bob.x && S_alice.y == S_bob.y
                                        ? "YES" : "NO") << "\n\n";

        /* ───────── BLOCK 3: HKDF ───────── */
        header("BLOCK 3", "HKDF-SHA256 - Key Derivation (RFC 5869)");

        /* Convert S.x → 32 bytes */
        std::string hex_x = S_alice.x.get_str(16);
        while (hex_x.size() < 64) hex_x = "0" + hex_x;
        uint8_t shared_x[32];
        hex_to_bytes(hex_x, shared_x, 32);

        std::string salt     = cfg_["hkdf.salt"];
        std::string info_enc = cfg_["hkdf.info_enc"];
        std::string info_mac = cfg_["hkdf.info_mac"];

        uint8_t k_enc[32], k_mac[32];

        hkdf_sha256(shared_x, 32,
                    (const uint8_t *)salt.c_str(), salt.size(),
                    (const uint8_t *)info_enc.c_str(), info_enc.size(),
                    k_enc, 32);
        hkdf_sha256(shared_x, 32,
                    (const uint8_t *)salt.c_str(), salt.size(),
                    (const uint8_t *)info_mac.c_str(), info_mac.size(),
                    k_mac, 32);

        std::cout << "  Input:\n";
        std::cout << "    IKM (S.x)  = " << to_hex(shared_x, 32) << "\n";
        std::cout << "    Salt       = \"" << salt << "\"\n";
        std::cout << "    Info (enc) = \"" << info_enc << "\"\n";
        std::cout << "    Info (mac) = \"" << info_mac << "\"\n\n";
        std::cout << "  Output:\n";
        std::cout << "    k_enc (AES-256 key) = " << to_hex(k_enc, 32) << "\n";
        std::cout << "    k_mac               = " << to_hex(k_mac, 32) << "\n\n";

        /* ───────── BLOCK 4: AES-256-GCM ENCRYPT ───────── */
        header("BLOCK 4", "AES-256-GCM Encryption (NIST SP 800-38D)");

        std::string iv_hex = cfg_["gcm.iv"];
        uint8_t iv[GCM_IV_LEN];
        hex_to_bytes(iv_hex, iv, GCM_IV_LEN);

        std::string aad = cfg_["gcm.aad"];

        std::vector<uint8_t> ciphertext(plaintext.size());
        uint8_t tag[GCM_TAG_LEN];

        gcm_encrypt(k_enc, iv,
                    (const uint8_t *)aad.c_str(), aad.size(),
                    (const uint8_t *)plaintext.c_str(), plaintext.size(),
                    ciphertext.data(), tag);

        std::cout << "  Input:\n";
        std::cout << "    Key (32 B)  = " << to_hex(k_enc, 32) << "\n";
        std::cout << "    IV  (12 B)  = " << to_hex(iv, GCM_IV_LEN) << "\n";
        std::cout << "    AAD         = \"" << aad << "\"\n";
        std::cout << "    Plaintext   = " << to_hex((const uint8_t *)plaintext.data(), plaintext.size()) << "\n\n";
        std::cout << "  Output:\n";
        std::cout << "    Ciphertext  = " << to_hex(ciphertext.data(), ciphertext.size()) << "\n";
        std::cout << "    Auth Tag    = " << to_hex(tag, GCM_TAG_LEN) << "\n\n";

        /* ───────── BLOCK 5: AES-256-GCM DECRYPT ───────── */
        header("BLOCK 5", "AES-256-GCM Decryption & Verification");

        std::vector<uint8_t> decrypted(ciphertext.size());
        int ret = gcm_decrypt(k_enc, iv,
                              (const uint8_t *)aad.c_str(), aad.size(),
                              ciphertext.data(), ciphertext.size(),
                              decrypted.data(), tag);

        std::string recovered(decrypted.begin(), decrypted.end());

        std::cout << "  Input:\n";
        std::cout << "    Ciphertext  = " << to_hex(ciphertext.data(), ciphertext.size()) << "\n";
        std::cout << "    Auth Tag    = " << to_hex(tag, GCM_TAG_LEN) << "\n\n";
        std::cout << "  Output:\n";
        std::cout << "    Decrypted (hex) = " << to_hex(decrypted.data(), decrypted.size()) << "\n";
        std::cout << "    Decrypted (str) = \"" << recovered << "\"\n";
        std::cout << "    Verification    : " << (ret == 0 ? "PASSED" : "FAILED") << "\n\n";

        separator("PIPELINE COMPLETE");
    }

private:
    std::map<std::string, std::string> cfg_;
    EllipticCurve ec_;

    /* ── helpers ── */
    static void hex_to_bytes(const std::string &hex, uint8_t *out, size_t len) {
        for (size_t i = 0; i < len && i * 2 + 1 < hex.size(); i++) {
            std::string b = hex.substr(i * 2, 2);
            out[i] = (uint8_t)strtol(b.c_str(), nullptr, 16);
        }
    }

    static std::string to_hex(const uint8_t *data, size_t len) {
        std::ostringstream ss;
        for (size_t i = 0; i < len; i++)
            ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
        return ss.str();
    }

    static void separator(const std::string &title) {
        std::cout << "==========================================================\n";
        std::cout << "  " << title << "\n";
        std::cout << "==========================================================\n\n";
    }

    static void header(const std::string &tag, const std::string &title) {
        std::cout << "----------------------------------------------------------\n";
        std::cout << "  [" << tag << "] " << title << "\n";
        std::cout << "----------------------------------------------------------\n";
    }
};

#endif /* ECC_ENCRYPT_H */
