#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include "../../../sockets/SSLContext.h"
#include <memory>
#include <string>
#include <vector>

/**
 * Specialized client for file sharing operations
 * Handles file sharing, share revocation, and share listing
 */
class SharingServiceClient {
public:
    SharingServiceClient(SSLContext& ssl_context, 
                        const std::string& host, 
                        const std::string& port);
    ~SharingServiceClient() = default;

    // File sharing operations
    FileShareResponse share_file(
        const FileShareRequest& request,
        const std::string& session_token);
    
    bool revoke_share(
        const std::string& share_id,
        const std::string& session_token);
    
    // Share listing and management
    std::vector<ShareResponse> list_file_shares(
        const std::string& file_id,
        const std::string& session_token);
    
    std::vector<SharedFileResponse> list_received_shares(
        const std::string& session_token,
        int limit = 50,
        int offset = 0);

private:
    SSLContext& ssl_context_;
    std::string server_host_;
    std::string server_port_;
}; 