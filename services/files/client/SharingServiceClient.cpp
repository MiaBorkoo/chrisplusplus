#include "SharingServiceClient.h"
#include "DataConverter.h"
#include "../../../httpC/HttpClient.h"
#include "../../../httpC/HttpRequest.h"
#include "../../../httpC/HttpResponse.h"
#include "../config/ServiceConfig.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <iostream>

SharingServiceClient::SharingServiceClient(SSLContext& ssl_context, 
                                          const std::string& host, 
                                          const std::string& port)
    : ssl_context_(ssl_context), server_host_(host), server_port_(port) {
}

FileShareResponse SharingServiceClient::share_file(
    const FileShareRequest& request,
    const std::string& session_token) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "POST";
        http_request.path = "/api/files/share";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["Content-Type"] = "application/json";
        http_request.headers["User-Agent"] = ServiceConfig::Client::USER_AGENT;
        http_request.body = DataConverter::to_json_string(request);
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::SHARE_CREATION_FAILED, 
                              "File share failed with status: " + std::to_string(response.statusCode));
        }
        
        return DataConverter::parse_json_response<FileShareResponse>(response.body);
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SHARE_CREATION_FAILED, 
                          std::string("File share failed: ") + e.what());
    }
}

bool SharingServiceClient::revoke_share(
    const std::string& share_id,
    const std::string& session_token) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "DELETE";
        http_request.path = "/api/files/share/" + share_id;
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["User-Agent"] = ServiceConfig::Client::USER_AGENT;
        
        HttpResponse response = client.sendRequest(http_request);
        
        return response.statusCode == 200;
        
    } catch (const std::exception& e) {
        return false;
    }
}

std::vector<ShareResponse> SharingServiceClient::list_file_shares(
    const std::string& file_id,
    const std::string& session_token) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "GET";
        http_request.path = "/api/files/" + file_id + "/shares";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["User-Agent"] = ServiceConfig::Client::USER_AGENT;
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                              "List file shares failed with status: " + std::to_string(response.statusCode));
        }
        
        // Parse JSON array response
        nlohmann::json j = nlohmann::json::parse(response.body);
        std::vector<ShareResponse> shares;
        
        for (const auto& share_json : j) {
            ShareResponse share;
            share.share_id = share_json["share_id"];
            share.file_id = share_json["file_id"];
            share.recipient_id = share_json["recipient_id"];
            
            // Handle granted_at - convert string to uint64_t if necessary
            if (share_json["granted_at"].is_string()) {
                share.granted_at = std::stoull(share_json["granted_at"].get<std::string>());
            } else {
                share.granted_at = share_json["granted_at"];
            }
            
            // Handle optional expires_at
            if (!share_json["expires_at"].is_null()) {
                if (share_json["expires_at"].is_string()) {
                    share.expires_at = std::stoull(share_json["expires_at"].get<std::string>());
                } else {
                    share.expires_at = share_json["expires_at"];
                }
            }
            
            // Handle optional revoked_at
            if (!share_json["revoked_at"].is_null()) {
                if (share_json["revoked_at"].is_string()) {
                    share.revoked_at = std::stoull(share_json["revoked_at"].get<std::string>());
                } else {
                    share.revoked_at = share_json["revoked_at"];
                }
            }
            
            shares.push_back(share);
        }
        
        return shares;
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("List file shares failed: ") + e.what());
    }
}

std::vector<SharedFileResponse> SharingServiceClient::list_received_shares(
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
        http_request.path = "/api/files/shares/received?" + query_string;
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["User-Agent"] = ServiceConfig::Client::USER_AGENT;
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                              "List received shares failed with status: " + std::to_string(response.statusCode));
        }
        
        // Parse JSON array response
        nlohmann::json j = nlohmann::json::parse(response.body);
        std::vector<SharedFileResponse> shared_files;
        
        for (const auto& file_json : j) {
            SharedFileResponse file;
            file.file_id = file_json["file_id"];
            file.filename_encrypted = file_json["filename_encrypted"];
            file.file_size_encrypted = file_json["file_size_encrypted"];
            file.upload_timestamp = file_json["upload_timestamp"];
            file.file_data_hmac = file_json["file_data_hmac"];
            file.share_id = file_json["share_id"];
            file.shared_by = file_json.value("shared_by", "");  // Get shared_by with empty string as default
            shared_files.push_back(file);
        }
        
        return shared_files;
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("List received shares failed: ") + e.what());
    }
} 