#pragma once

#include "../httpC/HttpClient.h"
#include "../sockets/SSLContext.h"
#include <QFile>
#include <QFileInfo>
#include <QString>
#include <functional>
#include <memory>

// Progress callback: (bytesTransferred, totalBytes) -> bool (continue?)
using ProgressCallback = std::function<bool(qint64, qint64)>;

// File metadata for uploads/downloads
struct FileMetadata {
    QString filename;
    QString mimeType;
    qint64 size;
    QString checksum; // For integrity verification
    
    FileMetadata() : size(0) {}
};

// Simple transfer result
struct TransferResult {
    bool success;
    QString errorMessage;
    qint64 bytesTransferred;
    QString serverResponse;
    
    TransferResult() : success(false), bytesTransferred(0) {}
};

class FileTransfer {
public:
    explicit FileTransfer(SSLContext& sslContext);
    ~FileTransfer() = default;

    // Configure the transfer client
    void setServer(const std::string& host, const std::string& port = "443");
    void setAuthToken(const QString& token);
    
    // Main operations (with built-in retry and error handling)
    TransferResult uploadFile(const QString& filePath, 
                            const std::string& uploadEndpoint,
                            const ProgressCallback& progressCallback = nullptr,
                            int maxRetries = 3);
    
    TransferResult downloadFile(const std::string& downloadEndpoint,
                              const QString& savePath,
                              const ProgressCallback& progressCallback = nullptr,
                              int maxRetries = 3);
    
    // Cancel ongoing transfer
    void cancelTransfer();

private:
    SSLContext& sslContext_;
    std::unique_ptr<HttpClient> httpClient_;
    std::string serverHost_;
    std::string serverPort_;
    QString authToken_;
    bool cancelRequested_;
    
    // Helper methods
    HttpRequest createUploadRequest(const std::string& endpoint, const QString& filename, qint64 fileSize);
    HttpRequest createDownloadRequest(const std::string& endpoint);
    TransferResult performUploadWithRetry(const QString& filePath, const std::string& endpoint, 
                                        const ProgressCallback& callback, int maxRetries);
    TransferResult performDownloadWithRetry(const std::string& endpoint, const QString& savePath,
                                          const ProgressCallback& callback, int maxRetries);
    QString extractServerError(const HttpResponse& response);
};

// Specialized transfer classes for different protocols
class SecureFileUploader {
public:
    explicit SecureFileUploader(FileTransfer& transfer) : transfer_(transfer) {}
    
    // High-level upload with automatic retry and validation
    TransferResult uploadWithRetry(const QString& filePath,
                                 const std::string& endpoint,
                                 int maxRetries = 3,
                                 const ProgressCallback& callback = nullptr);

private:
    FileTransfer& transfer_;
};

class SecureFileDownloader {
public:
    explicit SecureFileDownloader(FileTransfer& transfer) : transfer_(transfer) {}
    
    // High-level download with automatic validation
    TransferResult downloadWithValidation(const std::string& endpoint,
                                        const QString& savePath,
                                        const QString& expectedChecksum = "",
                                        const ProgressCallback& callback = nullptr);

private:
    FileTransfer& transfer_;
}; 