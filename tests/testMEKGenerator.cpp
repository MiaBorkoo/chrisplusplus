#include "../crypto/MEKGenerator.h"
#include <iostream>
#include <cassert>

int main() {
    auto mek = generateMEK();
    assert(mek.size() == 32);
    std::cout << "testMEKGenerator: PASS" << std::endl;
    return 0;
}