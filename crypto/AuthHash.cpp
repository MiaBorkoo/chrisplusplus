#include "AuthHash.h"
#include <argon2.h>
#include <random>
#include <stdexcept>

// generates a random salt of at least 16 bytes using std::random_device
std::vector<uint8_t> AuthHash::generateSalt(size_t length) {
    if (length < 16) length = 16; // enforce minimum salt length
    std::random_device rd;
    std::vector<uint8_t> salt(length);
    for (size_t i = 0; i < length; ++i) {
        salt[i] = static_cast<uint8_t>(rd() & 0xFF); // fill with random bytes
    }
    return salt;
}

// computes an authentication hash using argon2id
// takes a server auth key and a second salt (authSalt2)
// returns a 32-byte (256-bit) hash
std::vector<uint8_t> AuthHash::computeAuthHash(const std::vector<uint8_t>& serverAuthKey,
                                               const std::vector<uint8_t>& authSalt2) {
    if (serverAuthKey.size() < 32 || authSalt2.size() < 16) {
        throw std::invalid_argument("serverAuthKey or salt too small");
    }

    // Argon2id parameters
    uint32_t time_cost = 2;
    uint32_t memory_cost = 19 * 1024; //19 mib
    uint32_t parallelism = 1;

    std::vector<uint8_t> authHash(32); //256-bit hash output

    //run argon2id to compute the hash
    if (argon2id_hash_raw(time_cost, memory_cost, parallelism,
                          serverAuthKey.data(), serverAuthKey.size(),
                          authSalt2.data(), authSalt2.size(),
                          authHash.data(), authHash.size()) != ARGON2_OK) {
        throw std::runtime_error("argon2id failed during auth hash computation");
    }

    return authHash;
}