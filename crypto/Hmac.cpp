#include "Hmac.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>

std::vector<uint8_t> HMACProcessor::dataToBlob(const std::string& data) {
    return std::vector<uint8_t>(data.begin(), data.end());
}

std::vector<uint8_t> HMACProcessor::generateHMAC(const std::vector<uint8_t>& dataBlob, 
                                               const std::string& privateKey) {
    std::vector<uint8_t> hmac(SHA256_DIGEST_LENGTH);
    unsigned int hmacLength;
    
    HMAC(EVP_sha256(), 
         privateKey.c_str(), privateKey.length(),
         dataBlob.data(), dataBlob.size(),
         hmac.data(), &hmacLength);
    
    hmac.resize(hmacLength);
    return hmac;
}

bool HMACProcessor::verifyHMAC(const std::vector<uint8_t>& dataBlob,
                              const std::string& privateKey,
                              const std::vector<uint8_t>& providedHMAC) {
    std::vector<uint8_t> computedHMAC = generateHMAC(dataBlob, privateKey);
    
    if (computedHMAC.size() != providedHMAC.size()) {
        return false;
    }
    
    int result = 0;
    for (size_t i = 0; i < computedHMAC.size(); ++i) {
        result |= (computedHMAC[i] ^ providedHMAC[i]);
    }
    return result == 0;
}