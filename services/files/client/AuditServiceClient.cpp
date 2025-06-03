#include "AuditServiceClient.h"
#include "DataConverter.h"
#include "../../../httpC/HttpClient.h"
#include "../../../httpC/HttpRequest.h"
#include "../../../httpC/HttpResponse.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

AuditServiceClient::AuditServiceClient(SSLContext& ssl_context, 
                                      const std::string& host, 
                                      const std::string& port)
    : ssl_context_(ssl_context), server_host_(host), server_port_(port) {
}

std::vector<AuditLogResponse> AuditServiceClient::get_file_audit_logs(
    const std::string& file_id,
    const std::string& session_token,
    int limit,
    int offset) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        // Build query parameters
        std::map<std::string, std::string> params;
        params["limit"] = std::to_string(limit);
        params["offset"] = std::to_string(offset);
        std::string query_string = DataConverter::build_query_string(params);
        
        HttpRequest http_request;
        http_request.method = "GET";
        http_request.path = "/api/files/" + file_id + "/audit?" + query_string;
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                              "Get audit logs failed with status: " + std::to_string(response.statusCode));
        }
        
        // Parse JSON array response
        nlohmann::json j = nlohmann::json::parse(response.body);
        std::vector<AuditLogResponse> audit_logs;
        
        for (const auto& log_json : j) {
            AuditLogResponse log;
            log.log_id = log_json["log_id"];
            log.action = log_json["action"];
            log.timestamp = log_json["timestamp"];
            log.client_ip_hash = log_json["client_ip_hash"];
            audit_logs.push_back(log);
        }
        
        return audit_logs;
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("Get audit logs failed: ") + e.what());
    }
} 