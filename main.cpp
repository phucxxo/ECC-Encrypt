#include <iostream>
#include <string>
#include "src/core/ecc_encrypt.h"
//
//make clean && make 
//./ecc_encrypt

int main() {
    std::string plaintext;
    std::cout << "Nhap plaintext: ";
    std::getline(std::cin, plaintext);

    ECCEncrypt engine("configs/configs.yaml");
    engine.run(plaintext);

    return 0;
}
