#include "AuthHash.h"
#include <argon2.h>
#include <random>
#include <stdexcept>
#include <openssl/rand.h>

// generates a random salt of at least 16 bytes using OpenSSL RAND_bytes
std::vector<uint8_t> AuthHash::generateSalt(size_t length) {
    if (length < 16) length = 16; // enforce minimum salt length
    std::vector<uint8_t> salt(length);
    if (RAND_bytes(salt.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed to generate secure salt");
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