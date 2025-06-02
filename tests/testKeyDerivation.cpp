#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include "../crypto/KeyDerivation.h"
#include "../crypto/CryptoTypes.h"

int main() {
    KeyDerivation kd;
    std::string password = "SuperSecurePassword123!";

    //this generates salts
    std::vector<uint8_t> authSalt = kd.generateSalt();
    std::vector<uint8_t> encSalt = kd.generateSalt();

    std::cout << "Auth Salt (" << authSalt.size() << " bytes): ";
    for (auto b : authSalt) std::cout << std::hex << (int)b << " ";
    std::cout << std::dec << std::endl;

    std::cout << "Enc Salt (" << encSalt.size() << " bytes): ";
    for (auto b : encSalt) std::cout << std::hex << (int)b << " ";
    std::cout << std::dec << std::endl;

    //checking salt lengths
    assert(authSalt.size() >= 16);
    assert(encSalt.size() >= 16);

    //derive keys
    DerivedKeys keys = kd.deriveKeysFromPassword(password, authSalt, encSalt);

    std::cout << "Server Auth Key: ";
    for (auto b : keys.serverAuthKey) std::cout << std::hex << (int)b << " ";
    std::cout << std::dec << std::endl;

    std::cout << "MEK Wrapper Key: ";
    for (auto b : keys.mekWrapperKey) std::cout << std::hex << (int)b << " ";
    std::cout << std::dec << std::endl;

    //checking key lengths
    assert(keys.serverAuthKey.size() == 32);
    assert(keys.mekWrapperKey.size() == 32);

    //checking that salts are stored in DerivedKeys
    assert(keys.authSalt == authSalt);
    assert(keys.encSalt == encSalt);

    std::cout << "Key derivation and salt generation test passed!" << std::endl;
    return 0;
} 