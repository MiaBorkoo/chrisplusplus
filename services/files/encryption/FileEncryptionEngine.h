#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include "../compression/CompressionEngine.h"
#include "../serialization/SerializationEngine.h"
#include <vector>
#include <string>
#include <map>
#include <memory>

// Content type enumeration for template specialization
enum class ContentTypeEnum {
    FILE,
    FOLDER
};

// Content data structures for template functions
struct FileContent {
    std::string filename;
    std::vector<uint8_t> file_data;
    std::map<std::string, std::string> metadata;
    size_t original_size;
};

struct FolderContent {
    std::string folder_name;
    std::map<std::string, FileContent> files;  // relative_path -> FileContent
    std::map<std::string, FolderContent> subfolders;  // subfolder_name -> FolderContent
    std::map<std::string, std::string> metadata;
    size_t total_size;
    size_t file_count;
};

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
    
    // Template-based content encryption/decryption with compression
    template<typename ContentType>
    FileEncryptionContext encrypt_content(
        const ContentType& content_data,
        const std::vector<uint8_t>& mek,
        ContentTypeEnum content_type);
    
    template<typename ContentType>
    ContentType decrypt_content(
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
    // Engine dependencies
    std::unique_ptr<CompressionEngine> compression_engine_;
    std::unique_ptr<SerializationEngine> serialization_engine_;
    
    // Helper methods for OpenSSL operations
    std::vector<uint8_t> generate_random_bytes(size_t length);
    void secure_zero_memory(std::vector<uint8_t>& data);
}; 