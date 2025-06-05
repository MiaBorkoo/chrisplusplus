#include "KeyDerivation.h"
#include <argon2.h>
#include <stdexcept>
#include <openssl/rand.h>

DerivedKeys KeyDerivation::deriveKeysFromPassword(
    const std::string& password,
    const std::vector<uint8_t>& authSalt,
    const std::vector<uint8_t>& encSalt
) {
    DerivedKeys keys;

    if (authSalt.size() < 32 || encSalt.size() < 32) {
        throw std::invalid_argument("Salts must be at least 32 bytes");
    }

    //Argon2id parameters
    uint32_t time_cost = 2; // iterations(CPU time)
    uint32_t memory_cost = 19 * 1024; // 19 MiB in KiB -> how much memory to use
    uint32_t parallelism = 1; // degree of parallelism -> how many threads/cores to use

    //deriving Server Auth Key
    if (argon2id_hash_raw(time_cost, memory_cost, parallelism,
                          password.data(), password.size(),
                          authSalt.data(), authSalt.size(),
                          keys.serverAuthKey.data(), keys.serverAuthKey.size()) != ARGON2_OK) {
        throw std::runtime_error("Argon2id failed (serverAuthKey)");
    }

    //deriving MEK Wrapper Key
    if (argon2id_hash_raw(time_cost, memory_cost, parallelism,
                          password.data(), password.size(),
                          encSalt.data(), encSalt.size(),
                          keys.mekWrapperKey.data(), keys.mekWrapperKey.size()) != ARGON2_OK) {
        throw std::runtime_error("Argon2id failed (mekWrapperKey)");
    }

    keys.authSalt = authSalt;
    keys.encSalt = encSalt;

    return keys;
}

DerivedKeys KeyDerivation::deriveKeysFromPassword(
    const std::string& password,
    const std::vector<uint8_t>& authSalt
) {
    DerivedKeys keys;

    if (authSalt.size() < 32) {
        throw std::invalid_argument("Salt must be at least 32 bytes");
    }

    //Argon2id parameters
    uint32_t time_cost = 2; // iterations(CPU time)
    uint32_t memory_cost = 19 * 1024; // 19 MiB in KiB -> how much memory to use
    uint32_t parallelism = 1; // degree of parallelism -> how many threads/cores to use

    //deriving Server Auth Key
    if (argon2id_hash_raw(time_cost, memory_cost, parallelism,
                          password.data(), password.size(),
                          authSalt.data(), authSalt.size(),
                          keys.serverAuthKey.data(), keys.serverAuthKey.size()) != ARGON2_OK) {
        throw std::runtime_error("Argon2id failed (serverAuthKey)");
    }

    keys.authSalt = authSalt;
    return keys;
}
std::vector<uint8_t> KeyDerivation::generateSalt(size_t length) {
    std::vector<uint8_t> salt(32);
    if (RAND_bytes(salt.data(), 32) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed to generate secure salt");
    }

    return salt;
}