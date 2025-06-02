#include "../crypto/MEKGenerator.h"
#include <iostream>

int main() {
    auto mek = generateMEK();
    std::cout << "Generated MEK (32 bytes): ";
    for (auto byte : mek) {
        printf("%02x ", byte);
    }
    std::cout << "\n";
    return 0;
}