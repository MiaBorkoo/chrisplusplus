#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include "../compression/CompressionEngine.h"
#include <vector>
#include <string>
#include <map>
#include <memory>

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

    // Integration layer - Upload/Download flow helpers
    struct UploadPreparedData {
        std::vector<uint8_t> encrypted_content;     // Ready for multipart upload
        std::string filename_encrypted;             // Base64 encrypted filename
        std::string file_size_encrypted;            // Base64 encrypted original size
        std::string compressed_size_encrypted;      // Base64 encrypted compressed size (optional)
        std::string file_data_hmac;                 // HMAC of encrypted content
        FileEncryptionContext context;              // For later decryption
        ContentTypeEnum content_type;               // FILE or FOLDER
    };

    struct DownloadProcessedData {
        std::string original_filename;              // Decrypted filename
        size_t original_size;                       // Decrypted file size
        size_t compressed_size;                     // Decrypted compressed size
        ContentTypeEnum content_type;               // FILE or FOLDER
        bool integrity_verified;                    // HMAC verification result
        FileEncryptionContext context;              // For content decryption
    };

    // Prepare content for upload (encrypt content + metadata)
    template<typename ContentType>
    UploadPreparedData prepare_content_for_upload(
        const ContentType& content,
        const std::vector<uint8_t>& mek,
        ContentTypeEnum content_type);

    // Process download response (decrypt metadata, verify integrity)
    DownloadProcessedData process_download_response(
        const std::vector<uint8_t>& encrypted_content,
        const std::string& filename_encrypted,
        const std::string& file_size_encrypted, 
        const std::string& file_data_hmac,
        const std::vector<uint8_t>& mek,
        const FileEncryptionContext& context);

    // Decrypt downloaded content to original form
    template<typename ContentType>
    ContentType decrypt_downloaded_content(
        const std::vector<uint8_t>& encrypted_content,
        const DownloadProcessedData& processed_data);

    // Convenience functions for single operations
    UploadPreparedData prepare_file_for_upload(
        const std::string& filepath,
        const std::vector<uint8_t>& mek);
    
    UploadPreparedData prepare_folder_for_upload(
        const std::string& folder_path,
        const std::vector<uint8_t>& mek);

    // Helper methods (moved to public for testing)
    std::vector<uint8_t> generate_random_bytes(size_t length);
    void secure_zero_memory(std::vector<uint8_t>& data);

private:
    // Engine dependencies
    std::unique_ptr<CompressionEngine> compression_engine_;
}; 