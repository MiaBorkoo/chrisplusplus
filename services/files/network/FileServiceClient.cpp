#include "FileServiceClient.h"
#include "AuthServiceClient.h"
#include "FileOperationsClient.h"
#include "SharingServiceClient.h"
#include "AuditServiceClient.h"
#include "../../../sockets/SSLContext.h"

FileServiceClient::FileServiceClient() : base_url("https://localhost:8000") {
    // For HTTPS connections, initialize SSL
    use_ssl = true;
    SSLContext::initializeOpenSSL();
    ssl_context = std::make_unique<SSLContext>();
    
    // Disable certificate verification for development with self-signed certs
    ssl_context->disableCertificateVerification();
    
    server_host = "localhost";
    server_port = "8000";
    
    initialize_clients();
}

FileServiceClient::FileServiceClient(const std::string& base_url) : base_url(base_url) {
    // Always initialize SSL context, but configure it based on protocol
    SSLContext::initializeOpenSSL();
    ssl_context = std::make_unique<SSLContext>();
    
    // Parse URL to determine if SSL is needed
    if (base_url.find("https://") == 0) {
        use_ssl = true;
        // Disable certificate verification for development with self-signed certs
        ssl_context->disableCertificateVerification();
        server_port = "8000";  // Default HTTPS port for development
    } else {
        use_ssl = false;
        server_port = "8000";  // Default HTTP port
    }
    
    server_host = "localhost";
    
    initialize_clients();
}

FileServiceClient::~FileServiceClient() = default;

void FileServiceClient::set_server(const std::string& host, const std::string& port) {
    server_host = host;
    server_port = port;
    
    // Reinitialize clients with new server settings
    initialize_clients();
}

void FileServiceClient::set_base_url(const std::string& url) {
    base_url = url;
    // TODO: Parse URL to extract host and port
    // For now, keeping the existing server_host and server_port
    
    // Reinitialize clients with updated settings
    initialize_clients();
}

void FileServiceClient::initialize_clients() {
    if (!ssl_context) {
        return;  // Cannot initialize without SSL context
    }
    
    auth_client_ = std::make_unique<AuthServiceClient>(*ssl_context, server_host, server_port);
    file_client_ = std::make_unique<FileOperationsClient>(*ssl_context, server_host, server_port);
    sharing_client_ = std::make_unique<SharingServiceClient>(*ssl_context, server_host, server_port);
    audit_client_ = std::make_unique<AuditServiceClient>(*ssl_context, server_host, server_port);
}

// Authentication operations (delegated to AuthServiceClient)
AuthSessionResponse FileServiceClient::register_user(const RegisterRequest& request) {
    return auth_client_->register_user(request);
}

AuthSessionResponse FileServiceClient::login(const LoginRequest& request) {
    return auth_client_->login(request);
}

MEKResponse FileServiceClient::verify_totp(const TOTPRequest& request) {
    return auth_client_->verify_totp(request);
}

bool FileServiceClient::logout(const std::string& session_token) {
    return auth_client_->logout(session_token);
}

bool FileServiceClient::change_password(const ChangePasswordRequest& request) {
    return auth_client_->change_password(request);
}

UserSaltsResponse FileServiceClient::get_user_salts(const std::string& username) {
    return auth_client_->get_user_salts(username);
}

// File operations (delegated to FileOperationsClient)
FileUploadResponse FileServiceClient::upload_file(
    const std::vector<uint8_t>& encrypted_file_data,
    const FileUploadRequest& metadata,
    const std::string& session_token) {
    return file_client_->upload_file(encrypted_file_data, metadata, session_token);
}

FileDownloadResponse FileServiceClient::download_file(
    const std::string& file_id,
    const std::string& session_token) {
    return file_client_->download_file(file_id, session_token);
}

FileMetadataResponse FileServiceClient::get_file_metadata(
    const std::string& file_id,
    const std::string& session_token) {
    return file_client_->get_file_metadata(file_id, session_token);
}

UserFilesResponse FileServiceClient::list_files(
    const std::string& session_token,
    int limit,
    int offset) {
    return file_client_->list_files(session_token, limit, offset);
}

bool FileServiceClient::delete_file(
    const FileDeleteRequest& request,
    const std::string& session_token) {
    return file_client_->delete_file(request, session_token);
}

// Sharing operations (delegated to SharingServiceClient)
FileShareResponse FileServiceClient::share_file(
    const FileShareRequest& request,
    const std::string& session_token) {
    return sharing_client_->share_file(request, session_token);
}

bool FileServiceClient::revoke_share(
    const std::string& share_id,
    const std::string& session_token) {
    return sharing_client_->revoke_share(share_id, session_token);
}

std::vector<ShareResponse> FileServiceClient::list_file_shares(
    const std::string& file_id,
    const std::string& session_token) {
    return sharing_client_->list_file_shares(file_id, session_token);
}

std::vector<SharedFileResponse> FileServiceClient::list_received_shares(
    const std::string& session_token,
    int limit,
    int offset) {
    return sharing_client_->list_received_shares(session_token, limit, offset);
}

// Audit operations (delegated to AuditServiceClient)
std::vector<AuditLogResponse> FileServiceClient::get_file_audit_logs(
    const std::string& file_id,
    const std::string& session_token,
    int limit,
    int offset) {
    return audit_client_->get_file_audit_logs(file_id, session_token, limit, offset);
}

// Access to specialized clients for advanced usage
AuthServiceClient& FileServiceClient::auth_client() {
    return *auth_client_;
}

FileOperationsClient& FileServiceClient::file_client() {
    return *file_client_;
}

SharingServiceClient& FileServiceClient::sharing_client() {
    return *sharing_client_;
}

AuditServiceClient& FileServiceClient::audit_client() {
    return *audit_client_;
} 