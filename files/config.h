#ifndef CONFIG_H
#define CONFIG_H
#include <gmpxx.h>

namespace ECCConfig {
    inline mpz_class p() { return mpz_class("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"); }
    inline mpz_class a() { return mpz_class("0"); }
    inline mpz_class b() { return mpz_class("7"); }
    inline mpz_class Gx() { return mpz_class("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"); }
    inline mpz_class Gy() { return mpz_class("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"); }
    inline mpz_class n() { return mpz_class("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"); }
}
#endif