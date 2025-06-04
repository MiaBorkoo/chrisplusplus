#pragma once
#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Minimal RFC-6238 compliant TOTP generator.
 *
 *  • 30 s time-step (default)  
 *  • 6-digit code (default)  
 *  • HMAC-SHA-1 via OpenSSL 
 *
 * Example:
 *     TOTP totp("JBSWY3DPEHPK3PXP");   // base-32 secret
 *     std::string code = totp.generate();   // "492039"
 */
class TOTP {
public:
    explicit TOTP(const std::string& base32Secret,
                  std::uint32_t timeStepSeconds = 30,
                  std::uint32_t digits = 6);

    // Core TOTP functionality
    std::string generate(std::uint64_t unixTime = 0) const;
    bool verify(const std::string& code, int windowTolerance = 1) const;

    // Static utility methods
    static std::string generateSecret();
    static std::string createOTPAuthURL(const std::string& issuer, 
                                       const std::string& accountName, 
                                       const std::string& secret);

private:
    std::vector<std::uint8_t> secret_;
    std::uint32_t step_;
    std::uint32_t digits_;

    static std::vector<std::uint8_t> decodeBase32(const std::string& s);
    static std::string encodeBase32(const std::vector<std::uint8_t>& data);
};
