#include "WrappedMEK.h"
#include <openssl/rand.h>
#include <iostream>
#include <vector>

int main() {
    // create a random 32-byte wrapper key
    std::vector<uint8_t> wrapperKey(32);
    if (RAND_bytes(wrapperKey.data(), (int)wrapperKey.size()) != 1) {
        std::cerr << "failed to generate wrapper key" << std::endl;
        return 1;
    }

    // create a dummy mek (e.g. 16 bytes)
    std::vector<uint8_t> mek = {
        0x10, 0x20, 0x30, 0x40,
        0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0,
        0xd0, 0xe0, 0xf0, 0x00
    };

    try {
        EncryptedMEK encrypted = encryptMEKWithWrapperKey(mek, wrapperKey);

        // basic assertions
        if (encrypted.iv.size() != 12) {
            std::cerr << "error: iv length is not 12 bytes" << std::endl;
            return 1;
        }

        if (encrypted.tag.size() != 16) {
            std::cerr << "error: tag length is not 16 bytes" << std::endl;
            return 1;
        }

        if (encrypted.ciphertext.empty()) {
            std::cerr << "error: ciphertext is empty" << std::endl;
            return 1;
        }

        std::cout << "testWrappedMEK: PASS" << std::endl;

        // Test decryption
        try {
            std::vector<uint8_t> decrypted = decryptMEKWithWrapperKey(encrypted, wrapperKey);
            if (decrypted != mek) {
                std::cerr << "error: decrypted MEK does not match original" << std::endl;
                return 1;
            } else {
                std::cout << "testWrappedMEK decrypt: PASS" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "exception during decryption: " << e.what() << std::endl;
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "exception during encryption: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}