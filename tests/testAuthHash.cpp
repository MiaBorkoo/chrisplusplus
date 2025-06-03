#include "../crypto/AuthHash.h"
#include <iostream>
#include <cassert>
#include <algorithm>

void testComputeAuthHash() {
    //generate random serverAuthKey -> 32 bytes
    std::vector<uint8_t> serverAuthKey = AuthHash::generateSalt(32);
    std::vector<uint8_t> authSalt2 = AuthHash::generateSalt(16);

    std::vector<uint8_t> authHash = AuthHash::computeAuthHash(serverAuthKey, authSalt2);

    //checking hash length
    assert(authHash.size() == 32);

    //checking that hash isn't all zeros
    bool allZero = std::all_of(authHash.begin(), authHash.end(), [](uint8_t b) { return b == 0; });
    assert(!allZero);

    std::cout << "✅ AuthHash test passed.\n";
}

int main() {
    try {
        testComputeAuthHash();
    } catch (const std::exception& e) {
        std::cerr << "❌ Test failed: " << e.what() << '\n';
        return 1;
    }
    return 0;
}