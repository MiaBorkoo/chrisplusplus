#include "../crypto/Hmac.h"
#include <cassert>
#include <iostream>
#include <string>

void testValidHMAC() {
    std::cout << "Testing valid HMAC..." << std::endl;
    std::string testData = "Hello, HMAC!";
    std::string privateKey = "MySecretKey123";

    std::vector<uint8_t> dataBlob = HMACProcessor::dataToBlob(testData);
    std::vector<uint8_t> hmac = HMACProcessor::generateHMAC(dataBlob, privateKey);

    bool isValid = HMACProcessor::verifyHMAC(dataBlob, privateKey, hmac);
    assert(isValid && "Valid HMAC verification failed!");
    std::cout << "✅ Valid HMAC test passed" << std::endl;
}

void testInvalidHMAC() {
    std::cout << "Testing invalid HMAC..." << std::endl;
    std::string testData = "Hello, HMAC!";
    std::string privateKey = "MySecretKey123";

    std::vector<uint8_t> dataBlob = HMACProcessor::dataToBlob(testData);
    std::vector<uint8_t> hmac = HMACProcessor::generateHMAC(dataBlob, privateKey);

    dataBlob[0] ^= 1;  // Tamper with data
    bool isValid = HMACProcessor::verifyHMAC(dataBlob, privateKey, hmac);
    assert(!isValid && "Invalid HMAC verification unexpectedly passed!");
    std::cout << "✅ Invalid HMAC test passed" << std::endl;
}

int main() {
    try {
        testValidHMAC();
        testInvalidHMAC();
        std::cout << "\nAll HMAC tests passed! ✨" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with error: " << e.what() << std::endl;
        return 1;
    }
}
