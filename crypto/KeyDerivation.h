#pragma once
#include "IKeyDerivation.h"

class KeyDerivation : public IKeyDerivation {
public:
    DerivedKeys deriveKeysFromPassword(
        const std::string& password,
        const std::vector<uint8_t>& authSalt,
        const std::vector<uint8_t>& encSalt
    ) override;

    std::vector<uint8_t> generateSalt(size_t length = 16) override;
};