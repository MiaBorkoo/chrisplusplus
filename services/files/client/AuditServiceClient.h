#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include "../../../sockets/SSLContext.h"
#include <memory>
#include <string>
#include <vector>

/**
 * Specialized client for audit operations
 * Handles audit trail retrieval and logging operations
 */
class AuditServiceClient {
public:
    AuditServiceClient(SSLContext& ssl_context, 
                      const std::string& host, 
                      const std::string& port);
    ~AuditServiceClient() = default;

    // Audit trail operations
    std::vector<AuditLogResponse> get_file_audit_logs(
        const std::string& file_id,
        const std::string& session_token,
        int limit = 50,
        int offset = 0);

private:
    SSLContext& ssl_context_;
    std::string server_host_;
    std::string server_port_;
}; 