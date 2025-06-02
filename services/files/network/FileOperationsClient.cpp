#include "FileOperationsClient.h"
#include "DataConverter.h"
#include "../../../httpC/HttpClient.h"
#include "../../../httpC/HttpRequest.h"
#include "../../../httpC/HttpResponse.h"
#include <sstream>
#include <stdexcept>

FileOperationsClient::FileOperationsClient(SSLContext& ssl_context, 
                                          const std::string& host, 
                                          const std::string& port)
    : ssl_context_(ssl_context), server_host_(host), server_port_(port) {
}

FileUploadResponse FileOperationsClient::upload_file(
    const std::vector<uint8_t>& encrypted_file_data,
    const FileUploadRequest& metadata,
    const std::string& session_token) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        // Create multipart form data
        std::string boundary = DataConverter::create_multipart_boundary();
        std::string form_data = DataConverter::build_multipart_form_data(
            encrypted_file_data, metadata, boundary);
        
        HttpRequest http_request;
        http_request.method = "POST";
        http_request.path = "/api/files/upload";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["Content-Type"] = "multipart/form-data; boundary=" + boundary;
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        http_request.body = form_data;
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                              "File upload failed with status: " + std::to_string(response.statusCode));
        }
        
        return DataConverter::parse_json_response<FileUploadResponse>(response.body);
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("File upload failed: ") + e.what());
    }
}

FileDownloadResponse FileOperationsClient::download_file(
    const std::string& file_id,
    const std::string& session_token) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "GET";
        http_request.path = "/api/files/" + file_id + "/download";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::FILE_NOT_FOUND, 
                              "File download failed with status: " + std::to_string(response.statusCode));
        }
        
        return DataConverter::parse_json_response<FileDownloadResponse>(response.body);
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("File download failed: ") + e.what());
    }
}

FileMetadataResponse FileOperationsClient::get_file_metadata(
    const std::string& file_id,
    const std::string& session_token) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "GET";
        http_request.path = "/api/files/" + file_id + "/metadata";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::FILE_NOT_FOUND, 
                              "Get file metadata failed with status: " + std::to_string(response.statusCode));
        }
        
        return DataConverter::parse_json_response<FileMetadataResponse>(response.body);
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("Get file metadata failed: ") + e.what());
    }
}

UserFilesResponse FileOperationsClient::list_files(
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
        http_request.path = "/api/files/?" + query_string;
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                              "List files failed with status: " + std::to_string(response.statusCode));
        }
        
        return DataConverter::parse_json_response<UserFilesResponse>(response.body);
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("List files failed: ") + e.what());
    }
}

bool FileOperationsClient::delete_file(
    const FileDeleteRequest& request,
    const std::string& session_token) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "DELETE";
        http_request.path = "/api/files/delete";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["Content-Type"] = "application/json";
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        http_request.body = DataConverter::to_json_string(request);
        
        HttpResponse response = client.sendRequest(http_request);
        
        return response.statusCode == 200;
        
    } catch (const std::exception& e) {
        return false;
    }
} 