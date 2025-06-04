#pragma once
#include <vector>
#include <cstdint>

struct EncryptedMEK {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
};

EncryptedMEK encryptMEKWithWrapperKey(
    const std::vector<uint8_t>& mek,
    const std::vector<uint8_t>& mekWrapperKey
);

// Decrypt MEK using wrapper key (needed for TOTP secret decryption)
std::vector<uint8_t> decryptMEKWithWrapperKey(
    const EncryptedMEK& encrypted,
    const std::vector<uint8_t>& mekWrapperKey
);