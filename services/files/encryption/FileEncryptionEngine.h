#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include <vector>
#include <string>

class FileEncryptionEngine {
public:
    FileEncryptionEngine();
    ~FileEncryptionEngine() = default;

    // Core encryption/decryption
    FileEncryptionContext encrypt_file(
        const std::vector<uint8_t>& file_data,
        const std::vector<uint8_t>& mek);
    
    std::vector<uint8_t> decrypt_file(
        const std::vector<uint8_t>& encrypted_data,
        const FileEncryptionContext& context);
    
    // Integrity verification using HMAC
    std::string calculate_file_hmac(
        const std::vector<uint8_t>& file_data,
        const std::vector<uint8_t>& mek);
    
    bool verify_file_integrity(
        const std::vector<uint8_t>& file_data,
        const std::string& expected_hmac,
        const std::vector<uint8_t>& mek);
    
    // DEK management
    std::vector<uint8_t> generate_dek();
    std::vector<uint8_t> encrypt_dek_for_recipient(
        const std::vector<uint8_t>& dek,
        const nlohmann::json& recipient_public_key);
    std::vector<uint8_t> decrypt_dek_from_share(
        const std::vector<uint8_t>& encrypted_dek,
        const std::vector<uint8_t>& private_key);
    
    // Metadata encryption
    std::string encrypt_metadata(
        const std::string& data,
        const std::vector<uint8_t>& mek);
    std::string decrypt_metadata(
        const std::string& encrypted_data,
        const std::vector<uint8_t>& mek);
    
    // HMAC generation for sharing
    std::string generate_share_grant_hmac(
        const FileShareRequest& request,
        const std::vector<uint8_t>& mek);
    std::string generate_share_chain_hmac(
        const std::string& file_id,
        const std::string& recipient_username,
        const std::vector<uint8_t>& mek);

private:
    // Helper methods for libsodium operations
    std::vector<uint8_t> generate_random_bytes(size_t length);
    void secure_zero_memory(std::vector<uint8_t>& data);
}; 