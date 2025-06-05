#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include "../../../sockets/SSLContext.h"
#include <memory>
#include <string>

// Forward declarations of specialized clients
class FileOperationsClient;
class SharingServiceClient;
class AuditServiceClient;

/**
 * Main file service client that aggregates functionality from specialized clients
 * Handles file operations, sharing, and audit - authentication is handled separately
 */
class FileServiceClient {
public:
    FileServiceClient();
    FileServiceClient(const std::string& base_url);
    ~FileServiceClient(); // Declare but don't default - will be defined in .cpp

    // Configuration
    void set_server(const std::string& host, const std::string& port = "443");
    void set_base_url(const std::string& url);
    
    // File operations (delegated to FileOperationsClient)
    FileUploadResponse upload_file(
        const std::vector<uint8_t>& encrypted_file_data,
        const FileUploadRequest& metadata,
        const std::string& session_token);
    
    FileDownloadResponse download_file(
        const std::string& file_id,
        const std::string& session_token);
    
    // Download file directly to disk (convenience method)
    bool download_file_to_disk(
        const std::string& file_id,
        const std::string& output_path,
        const std::string& session_token);
    
    // Download file using stream method to avoid binary corruption
    bool download_file_stream(
        const std::string& file_id,
        const std::string& output_path,
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
    
    // Sharing operations (delegated to SharingServiceClient)
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
    
    // Audit operations (delegated to AuditServiceClient)
    std::vector<AuditLogResponse> get_file_audit_logs(
        const std::string& file_id,
        const std::string& session_token,
        int limit = 50,
        int offset = 0);

    // Access to specialized clients for advanced usage
    FileOperationsClient& file_client();
    SharingServiceClient& sharing_client();
    AuditServiceClient& audit_client();

private:
    std::string base_url;
    std::string server_host;
    std::string server_port;
    bool use_ssl;
    std::unique_ptr<SSLContext> ssl_context;
    
    // Specialized clients
    std::unique_ptr<FileOperationsClient> file_client_;
    std::unique_ptr<SharingServiceClient> sharing_client_;
    std::unique_ptr<AuditServiceClient> audit_client_;
    
    void initialize_clients();
}; 