#ifndef AUTH_HASH_H
#define AUTH_HASH_H

#include <cstdint>
#include <vector>

class AuthHash {
public:
    static std::vector<uint8_t> generateSalt(size_t length = 16);
    static std::vector<uint8_t> computeAuthHash(const std::vector<uint8_t>& serverAuthKey,
                                                const std::vector<uint8_t>& authSalt2);
};

#endif // AUTH_HASH_H