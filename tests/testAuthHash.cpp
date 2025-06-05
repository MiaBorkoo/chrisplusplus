#include "../crypto/AuthHash.h"
#include <iostream>
#include <cassert>
#include <algorithm>

void testComputeAuthHash() {
    //generate random serverAuthKey -> 32 bytes
    std::vector<uint8_t> serverAuthKey = AuthHash::generateSalt();
    std::vector<uint8_t> authSalt2 = AuthHash::generateSalt();

    std::vector<uint8_t> authHash = AuthHash::computeAuthHash(serverAuthKey, authSalt2);

    //checking hash length
    assert(authHash.size() == 32);

    //checking that hash isn't all zeros
    bool allZero = std::all_of(authHash.begin(), authHash.end(), [](uint8_t b) { return b == 0; });
    assert(!allZero);
}

int main() {
    try {
        testComputeAuthHash();
        std::cout << "testAuthHash: PASS" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "testAuthHash: FAIL - " << e.what() << '\n';
        return 1;
    }
    return 0;
}