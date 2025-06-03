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

    //checking salt lengths
    assert(authSalt.size() >= 16);
    assert(encSalt.size() >= 16);

    //derive keys
    DerivedKeys keys = kd.deriveKeysFromPassword(password, authSalt, encSalt);

    //checking key lengths
    assert(keys.serverAuthKey.size() == 32);
    assert(keys.mekWrapperKey.size() == 32);

    //checking that salts are stored in DerivedKeys
    assert(keys.authSalt == authSalt);
    assert(keys.encSalt == encSalt);

    std::cout << "testKeyDerivation: PASS" << std::endl;
    return 0;
} 