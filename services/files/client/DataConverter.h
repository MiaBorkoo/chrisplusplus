#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/bio.h>
#include <openssl/evp.h>

class DataConverter {
public:
    // Base64 encoding/decoding for JSON binary fields
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
    
    // Multipart form data handling
    static std::string create_multipart_boundary();
    static std::string build_multipart_form_data(
        const std::vector<uint8_t>& file_data,
        const FileUploadRequest& metadata,
        const std::string& boundary);
    
    // Convert internal formats to API formats
    static FileShareRequest to_api_share_request(
        const std::string& file_id,
        const std::string& recipient_username,
        const std::vector<uint8_t>& encrypted_dek,
        const std::string& share_grant_hmac,
        const std::string& share_chain_hmac,
        std::optional<uint64_t> expires_at = std::nullopt);
    
    // Convert API responses to internal formats
    static std::vector<uint8_t> extract_binary_from_api(const std::string& base64_data);
    
    // Helper for creating URL query parameters
    static std::string build_query_string(const std::map<std::string, std::string>& params);
    
    // JSON serialization helpers
    static std::string to_json_string(const RegisterRequest& request);
    static std::string to_json_string(const LoginRequest& request);
    static std::string to_json_string(const TOTPRequest& request);
    static std::string to_json_string(const ChangePasswordRequest& request);
    static std::string to_json_string(const FileShareRequest& request);
    static std::string to_json_string(const FileDeleteRequest& request);
    
    // JSON parsing helpers
    template<typename T>
    static T parse_json_response(const std::string& json_body);
    
private:
    static std::string escape_json_string(const std::string& str);
    static std::string hex_encode(const std::vector<uint8_t>& data);
}; 