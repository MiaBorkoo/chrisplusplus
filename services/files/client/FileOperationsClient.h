#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include "../../../sockets/SSLContext.h"
#include <memory>
#include <string>
#include <vector>

/**
 * Specialized client for file operations
 * Handles file upload, download, metadata, listing, and deletion
 */
class FileOperationsClient {
public:
    FileOperationsClient(SSLContext& ssl_context, 
                        const std::string& host, 
                        const std::string& port);
    ~FileOperationsClient() = default;

    // File upload and download
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
    
    // File metadata operations
    FileMetadataResponse get_file_metadata(
        const std::string& file_id,
        const std::string& session_token);
    
    UserFilesResponse list_files(
        const std::string& session_token,
        int limit = 50,
        int offset = 0);
    
    // File management
    bool delete_file(
        const FileDeleteRequest& request,
        const std::string& session_token);

private:
    SSLContext& ssl_context_;
    std::string server_host_;
    std::string server_port_;
}; 