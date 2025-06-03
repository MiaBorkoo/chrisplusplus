#include "FileOperationsClient.h"
#include "DataConverter.h"
#include "../../../httpC/HttpClient.h"
#include "../../../httpC/HttpRequest.h"
#include "../../../httpC/HttpResponse.h"
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <QFile>
#include <cstring>

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
        
        std::cout << "Making file upload request to: " << http_request.path << std::endl;
        std::cout << "Content-Type: " << http_request.headers["Content-Type"] << std::endl;
        std::cout << "Body size: " << form_data.size() << " bytes" << std::endl;
        
        HttpResponse response = client.sendRequest(http_request);
        
        std::cout << "Upload response status: " << response.statusCode << std::endl;
        std::cout << "Upload response body: " << response.body << std::endl;
        
        if (response.statusCode != 200) {
            std::cout << "File upload error - Status: " << response.statusCode << std::endl;
            std::cout << "Response body: " << response.body << std::endl;
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
        
        std::cout << "Making file download request to: " << http_request.path << std::endl;
        
        HttpResponse response = client.sendRequest(http_request);
        
        std::cout << "Download response status: " << response.statusCode << std::endl;
        std::cout << "Download response headers:" << std::endl;
        for (const auto& [key, value] : response.headers) {
            std::cout << "  " << key << ": " << value << std::endl;
        }
        std::cout << "Download response body size: " << response.body.size() << " bytes" << std::endl;
        
        if (response.statusCode != 200) {
            std::cout << "File download error - Status: " << response.statusCode << std::endl;
            std::cout << "Response body: " << response.body << std::endl;
            throw FileException(FileError::FILE_NOT_FOUND, 
                              "File download failed with status: " + std::to_string(response.statusCode));
        }
        
        // Check Content-Type to determine response format
        auto content_type_it = response.headers.find("Content-Type");
        bool is_json = (content_type_it != response.headers.end() && 
                       content_type_it->second.find("application/json") != std::string::npos);
        
        if (is_json) {
            // Server returned JSON with metadata and base64-encoded data
            std::cout << "Processing JSON download response" << std::endl;
            return DataConverter::parse_json_response<FileDownloadResponse>(response.body);
        } else {
            // Server returned binary data directly
            std::cout << "Processing binary download response" << std::endl;
            std::cout << "Raw response body length: " << response.body.length() << " bytes" << std::endl;
            std::cout << "Raw response body size(): " << response.body.size() << " bytes" << std::endl;
            
            FileDownloadResponse file_response;
            
            // Convert response body string to binary data
            // DEBUG: Check for potential string truncation issues
            std::cout << "Converting string to vector<uint8_t>..." << std::endl;
            
            // FIXED: Use raw data pointer to handle null bytes properly
            file_response.file_data.resize(response.body.size());
            if (!response.body.empty()) {
                std::memcpy(file_response.file_data.data(), response.body.data(), response.body.size());
            }
            
            std::cout << "Converted data size: " << file_response.file_data.size() << " bytes" << std::endl;
            
            // Debug: Show last few bytes of both string and vector
            if (response.body.size() >= 5) {
                std::cout << "Last 5 bytes of string: ";
                for (size_t i = response.body.size() - 5; i < response.body.size(); ++i) {
                    std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) 
                              << (unsigned char)response.body[i] << " ";
                }
                std::cout << std::dec << std::endl;
            }
            
            if (file_response.file_data.size() >= 5) {
                std::cout << "Last 5 bytes of vector: ";
                for (size_t i = file_response.file_data.size() - 5; i < file_response.file_data.size(); ++i) {
                    std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) 
                              << (unsigned int)file_response.file_data[i] << " ";
                }
                std::cout << std::dec << std::endl;
            }
            
            // Extract metadata from headers if available
            auto filename_it = response.headers.find("X-Filename-Encrypted");
            if (filename_it != response.headers.end()) {
                file_response.filename_encrypted = filename_it->second;
            } else {
                file_response.filename_encrypted = file_id; // Fallback to file_id
            }
            
            auto filesize_it = response.headers.find("X-File-Size-Encrypted");
            if (filesize_it != response.headers.end()) {
                file_response.file_size_encrypted = filesize_it->second;
            } else {
                file_response.file_size_encrypted = std::to_string(file_response.file_data.size());
            }
            
            auto hmac_it = response.headers.find("X-File-Data-HMAC");
            if (hmac_it != response.headers.end()) {
                file_response.file_data_hmac = hmac_it->second;
            } else {
                file_response.file_data_hmac = ""; // Empty if not provided
            }
            
            return file_response;
        }
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("File download failed: ") + e.what());
    }
}

bool FileOperationsClient::download_file_to_disk(
    const std::string& file_id,
    const std::string& output_path,
    const std::string& session_token) {
    try {
        // Download the file
        FileDownloadResponse download_response = download_file(file_id, session_token);
        
        // WORKAROUND: Remove padding byte that was added to compensate for HttpResponse::parse bug
        std::vector<uint8_t> actual_data = download_response.file_data;
        if (!actual_data.empty()) {
            // Remove the last byte which should be our 0xFF padding
            actual_data.pop_back();
        }
        
        // Write to disk
        std::ofstream output_file(output_path, std::ios::binary);
        if (!output_file.is_open()) {
            throw FileException(FileError::FILE_SYSTEM_ERROR, 
                              "Failed to open output file: " + output_path);
        }
        
        output_file.write(reinterpret_cast<const char*>(actual_data.data()),
                         actual_data.size());
        output_file.close();
        
        std::cout << "File downloaded successfully to: " << output_path << std::endl;
        std::cout << "File size: " << actual_data.size() << " bytes (padding removed)" << std::endl;
        std::cout << "Filename (encrypted): " << download_response.filename_encrypted << std::endl;
        
        return true;
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::FILE_SYSTEM_ERROR, 
                          std::string("File download to disk failed: ") + e.what());
    }
}

bool FileOperationsClient::download_file_stream(
    const std::string& file_id,
    const std::string& output_path,
    const std::string& session_token) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        // Create the request
        HttpRequest http_request;
        http_request.method = "GET";
        http_request.path = "/api/files/" + file_id + "/download";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        
        std::cout << "Making streaming file download request to: " << http_request.path << std::endl;
        
        // Open the output file for writing
        QFile output_file(QString::fromStdString(output_path));
        if (!output_file.open(QIODevice::WriteOnly)) {
            throw FileException(FileError::FILE_SYSTEM_ERROR, 
                              "Failed to open output file for writing: " + output_path);
        }
        
        // Use downloadToStream to avoid string conversion issues
        bool success = client.downloadToStream(http_request, output_file);
        
        qint64 file_size = output_file.size();
        output_file.close();
        
        if (success) {
            std::cout << "   ✓ File streamed successfully to: " << output_path << std::endl;
            std::cout << "   File size: " << file_size << " bytes" << std::endl;
            return true;
        } else {
            std::cout << "   ✗ File streaming failed" << std::endl;
            // Clean up the partial file
            QFile::remove(QString::fromStdString(output_path));
            return false;
        }
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::FILE_SYSTEM_ERROR, 
                          std::string("File stream download failed: ") + e.what());
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