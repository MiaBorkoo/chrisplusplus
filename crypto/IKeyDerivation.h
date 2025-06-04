#pragma once
#include "CryptoTypes.h"
#include <cstdint>
#include <string>

class IKeyDerivation {
public:
    virtual ~IKeyDerivation() = default;

//derives keys from a password and two salts
    virtual DerivedKeys deriveKeysFromPassword(
        const std::string& password,
        const std::vector<uint8_t>& authSalt,
        const std::vector<uint8_t>& encSalt
    ) = 0;

    virtual DerivedKeys deriveKeysFromPassword(
        const std::string& password,
        const std::vector<uint8_t>& authSalt
    ) = 0;

    //generates a random salt
    virtual std::vector<uint8_t> generateSalt(size_t length = 16) = 0;
};