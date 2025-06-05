#pragma once
#include <array>
#include <vector>
#include <cstdint>
#include <cstddef>

constexpr size_t KEY_LEN = 32; // this is 256 bits

struct DerivedKeys {
    std::array<uint8_t, KEY_LEN> serverAuthKey;
    std::array<uint8_t, KEY_LEN> mekWrapperKey;
    std::vector<uint8_t> authSalt;
    std::vector<uint8_t> encSalt;
};

//std::array for fixed-size secure keys
//std::vector for salts (which vary in size)