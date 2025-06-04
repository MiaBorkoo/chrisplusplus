#include "MEKGenerator.h"
#include <openssl/rand.h>
#include <stdexcept>

std::vector<unsigned char> generateMEK(size_t length) {
    std::vector<unsigned char> mek(length);
    // using OpenSSL's RAND_bytes fills the buffer with cryptographically secure random bytes->good for symmetric encryption key 
    if (RAND_bytes(mek.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("Failed to generate MEK");
    }
    return mek;
}