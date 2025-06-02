#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <map>

// Forward declaration for content types
enum class ContentTypeEnum {
    FILE,
    FOLDER
};

// Content data structures
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

// API Request/Response Models
struct RegisterRequest {
    std::string username;
    std::string auth_salt;
    std::string enc_salt;
    std::string auth_key;
    std::string encrypted_mek;
    std::string totp_secret;
    nlohmann::json public_key;
    std::string user_data_hmac;
};

struct LoginRequest {
    std::string username;
    std::string auth_key;
};

struct TOTPRequest {
    std::string username;
    std::string totp_code;
};

struct TOTPResponse {
    std::string session_token;
    std::string encrypted_mek;
    uint64_t expires_at;
};

struct ChangePasswordRequest {
    std::string username;
    std::string old_auth_key;
    std::string new_auth_key;
    std::string new_encrypted_mek;
    std::string totp_code;
};

struct UserSaltsResponse {
    std::string auth_salt;
    std::string enc_salt;
};

struct FileUploadRequest {
    std::vector<uint8_t> file;
    std::string file_id;
    std::string filename_encrypted;
    std::string file_size_encrypted;
    std::string file_data_hmac;
};

struct FileUploadResponse {
    std::string file_id;
    std::string server_storage_path;
    uint64_t upload_timestamp;
};

struct FileDownloadResponse {
    std::vector<uint8_t> file_data;
    std::string filename_encrypted;
    std::string file_size_encrypted;
    std::string file_data_hmac;
};

struct FileMetadataResponse {
    std::string file_id;
    std::string filename_encrypted;
    std::string file_size_encrypted;
    uint64_t upload_timestamp;
    std::string file_data_hmac;
    std::string server_storage_path;
};

struct FileShareRequest {
    std::string file_id;
    std::string recipient_username;
    std::vector<uint8_t> encrypted_data_key;
    std::optional<uint64_t> expires_at;
    std::string share_grant_hmac;
    std::string share_chain_hmac;
};

struct FileShareResponse {
    std::string share_id;
    uint64_t granted_at;
};

struct ShareRevokeResponse {
    bool success;
    uint64_t revoked_at;
};

struct FileResponse {
    std::string file_id;
    std::string filename_encrypted;
    std::string file_size_encrypted;
    uint64_t upload_timestamp;
    std::string file_data_hmac;
    std::string server_storage_path;
};

struct SharedFileResponse {
    std::string file_id;
    std::string filename_encrypted;
    std::string file_size_encrypted;
    uint64_t upload_timestamp;
    std::string file_data_hmac;
    std::string share_id;
};

struct UserFilesResponse {
    std::vector<FileResponse> owned_files;
    std::vector<SharedFileResponse> shared_files;
};

struct ShareResponse {
    std::string share_id;
    std::string file_id;
    std::string recipient_id;
    uint64_t granted_at;
    std::optional<uint64_t> expires_at;
    std::optional<uint64_t> revoked_at;
};

struct AuditLogResponse {
    std::string log_id;
    std::string action;
    uint64_t timestamp;
    std::string client_ip_hash;
};

struct FileDeleteRequest {
    std::string file_id;
};

// Internal Encryption Models
struct FileEncryptionContext {
    std::vector<uint8_t> dek;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> auth_tag;
    std::string file_id;
    size_t original_size;
    size_t compressed_size;
    std::string hmac;
    ContentTypeEnum content_type;
    bool is_compressed;
};

struct UserCryptoContext {
    std::vector<uint8_t> mek;
    std::vector<uint8_t> private_key;
    nlohmann::json public_key;
    std::string session_token;
    uint64_t session_expires_at;
};

struct ShareCryptoContext {
    std::vector<uint8_t> dek;
    std::string share_id;
    std::string owner_username;
    bool has_expired;
    bool is_revoked;
};

// User Interface Helper Structures
struct FileInfo {
    std::string file_id;
    std::string filename;
    size_t file_size;
    uint64_t upload_timestamp;
    bool integrity_verified;
};

struct SharedFileInfo : public FileInfo {
    std::string share_id;
    std::string owner_username;
    uint64_t shared_at;
    std::optional<uint64_t> expires_at;
};

struct ShareInfo {
    std::string share_id;
    std::string recipient_username;
    uint64_t granted_at;
    std::optional<uint64_t> expires_at;
    std::optional<uint64_t> revoked_at;
    bool is_active;
};

struct AuditInfo {
    std::string action;
    uint64_t timestamp;
    std::string client_ip_hash;
};

// Authentication Models
struct AuthSessionRequest {
    std::string username;
    std::string auth_key;
};

struct AuthSessionResponse {
    bool login_success;
    std::string totp_challenge_token;
    std::string session_token;
};

struct MEKRequest {
    std::string username;
    std::string totp_code;
};

struct MEKResponse {
    bool success;
    std::string session_token;
    std::string encrypted_mek;
    uint64_t expires_at;
};

struct UserKeyInfo {
    std::string username;
    nlohmann::json public_key;
    bool is_active;
};

// TOFU Models
struct IdentityVerificationRequest {
    std::string recipient_username;
    std::vector<uint8_t> recipient_public_key;
    std::string sharing_context;
};

struct IdentityVerificationResponse {
    bool is_trusted;
    std::string trust_level;
    std::vector<uint8_t> verified_public_key;
    uint64_t verification_timestamp;
}; 