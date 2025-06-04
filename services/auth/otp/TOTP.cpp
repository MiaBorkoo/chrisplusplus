#include "TOTP.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>

using namespace std::chrono;


TOTP::TOTP(const std::string& base32Secret,
           std::uint32_t timeStepSeconds,
           std::uint32_t digits)
    : secret_(decodeBase32(base32Secret)),
      step_(timeStepSeconds),
      digits_(digits)
{
    if (secret_.empty())  throw std::invalid_argument("secret is empty");
    if (digits_ < 6 || digits_ > 8)
        throw std::invalid_argument("digits must be 6-8");
}
    
std::string TOTP::generate(std::uint64_t unixTime) const
{   
    if (unixTime == 0)
        unixTime = duration_cast<seconds>(
                       system_clock::now().time_since_epoch()).count();

    std::uint64_t counter = unixTime / step_;
    unsigned char msg[8]{};
    for (int i = 7; i >= 0; --i) { msg[i] = counter & 0xFF; counter >>= 8; }

    unsigned char h[EVP_MAX_MD_SIZE];
    unsigned int   hLen = 0;
    HMAC(EVP_sha1(), secret_.data(), static_cast<int>(secret_.size()),
         msg, sizeof msg, h, &hLen);

    std::uint8_t  off = h[hLen - 1] & 0x0F;
    std::uint32_t bin = ((h[off] & 0x7F) << 24) |
                        ((h[off+1] & 0xFF) << 16) |
                        ((h[off+2] & 0xFF) << 8 ) |
                        ( h[off+3] & 0xFF);

    std::uint32_t mod = 1;
    for (std::uint32_t i = 0; i < digits_; ++i) mod *= 10;
    std::uint32_t code = bin % mod;

    std::ostringstream oss;
    oss << std::setw(digits_) << std::setfill('0') << code;
    return oss.str();
}


// based on RFC 4648 base-32 decode (A-Z 2-7, case-insensitive, no padding required)
std::vector<std::uint8_t> TOTP::decodeBase32(const std::string& s)
{
    auto val = [](char c)->int {
        if ('A'<=c && c<='Z') return  c-'A';
        if ('a'<=c && c<='z') return  c-'a';
        if ('2'<=c && c<='7') return  c-'2'+26;
        return -1;
    };
    std::vector<std::uint8_t> out;
    int buffer = 0, bits = 0;
    for (char c : s)
    {
        int v = val(c);
        if (v < 0) continue;          // ignore space, '=', and so on
        buffer = (buffer << 5) | v;
        bits  += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((buffer >> bits) & 0xFF);
        }
    }
    return out;
}
