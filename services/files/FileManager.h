#pragma once

#include "models/DataModels.h"
#include "network/FileServiceClient.h"
#include "encryption/FileEncryptionEngine.h"
#include "interfaces/Interfaces.h"
#include "exceptions/Exceptions.h"
#include <memory>
#include <vector>
#include <string>
#include <optional>

class FileManager {
public:
    FileManager(std::shared_ptr<FileServiceClient> client, 
                std::shared_ptr<FileEncryptionEngine> encryption,
                std::shared_ptr<TOFUInterface> tofu);
    
    ~FileManager() = default;

    // File operations
    std::string upload_file(
        const std::string& local_filepath,
        const std::string& session_token);
    
    bool download_file(
        const std::string& file_id,
        const std::string& local_output_path,
        const std::string& session_token);
    
    std::vector<FileInfo> list_user_files(
        const std::string& session_token);
    
    std::vector<SharedFileInfo> list_shared_files(
        const std::string& session_token);
    
    // File metadata (decrypted for user)
    FileInfo get_file_info(
        const std::string& file_id,
        const std::string& session_token);
    
    bool delete_file(
        const std::string& file_id,
        const std::string& session_token);
    
    // Sharing operations with TOFU verification
    std::string share_file_with_verification(
        const std::string& file_id,
        const std::string& recipient_username,
        const std::string& session_token,
        std::optional<uint64_t> expires_at = std::nullopt);
    
    bool revoke_file_share(
        const std::string& share_id,
        const std::string& session_token);
    
    std::vector<ShareInfo> list_file_shares(
        const std::string& file_id,
        const std::string& session_token);
    
    std::vector<AuditInfo> get_file_audit_trail(
        const std::string& file_id,
        const std::string& session_token);

private:
    std::shared_ptr<FileServiceClient> http_client;
    std::shared_ptr<FileEncryptionEngine> encryption_engine;
    std::shared_ptr<TOFUInterface> tofu_interface;
    
    // Helper methods
    std::vector<uint8_t> read_file_from_disk(const std::string& filepath);
    bool write_file_to_disk(const std::string& filepath, const std::vector<uint8_t>& data);
    std::vector<uint8_t> get_user_mek(const std::string& session_token);
    UserCryptoContext get_user_crypto_context(const std::string& session_token);
}; 