#pragma once

#include <string>
#include <vector>
#include <cstdint>

class HMACProcessor {
public:
    static std::vector<uint8_t> dataToBlob(const std::string& data);
    
    static std::vector<uint8_t> generateHMAC(const std::vector<uint8_t>& dataBlob, 
                                           const std::string& privateKey);
    
    static bool verifyHMAC(const std::vector<uint8_t>& dataBlob,
                          const std::string& privateKey,
                          const std::vector<uint8_t>& providedHMAC);
};
