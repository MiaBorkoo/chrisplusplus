#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include <memory>

class HTTPClient {
public:
    HTTPClient();
    ~HTTPClient() = default;

    // Authentication operations
    AuthSessionResponse register_user(const RegisterRequest& request);
    AuthSessionResponse login(const LoginRequest& request);
    MEKResponse verify_totp(const TOTPRequest& request);
    bool logout(const std::string& session_token);
    bool change_password(const ChangePasswordRequest& request);
    UserSaltsResponse get_user_salts(const std::string& username);
    
    // File operations
    FileUploadResponse upload_file(
        const std::vector<uint8_t>& encrypted_file_data,
        const FileUploadRequest& metadata,
        const std::string& session_token);
    
    FileDownloadResponse download_file(
        const std::string& file_id,
        const std::string& session_token);
    
    FileMetadataResponse get_file_metadata(
        const std::string& file_id,
        const std::string& session_token);
    
    UserFilesResponse list_files(
        const std::string& session_token,
        int limit = 50,
        int offset = 0);
    
    bool delete_file(
        const FileDeleteRequest& request,
        const std::string& session_token);
    
    // Sharing operations
    FileShareResponse share_file(
        const FileShareRequest& request,
        const std::string& session_token);
    
    bool revoke_share(
        const std::string& share_id,
        const std::string& session_token);
    
    std::vector<ShareResponse> list_file_shares(
        const std::string& file_id,
        const std::string& session_token);
    
    std::vector<SharedFileResponse> list_received_shares(
        const std::string& session_token,
        int limit = 50,
        int offset = 0);
    
    // Audit operations
    std::vector<AuditLogResponse> get_file_audit_logs(
        const std::string& file_id,
        const std::string& session_token,
        int limit = 50,
        int offset = 0);

private:
    std::string base_url;
}; 