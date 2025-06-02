#pragma once

#include "../httpC/HttpClient.h"
#include "../sockets/SSLContext.h"
#include <QObject>
#include <QTimer>
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

// CHANGE: Make it inherit from QObject
class FileTransfer : public QObject {
    Q_OBJECT
    
public:
    explicit FileTransfer(SSLContext& sslContext, QObject* parent = nullptr);
    ~FileTransfer() = default;

    // Configure the transfer client
    void setServer(const std::string& host, const std::string& port = "443");
    void setAuthToken(const QString& token);
    
    // Main operations (with built-in retry and error handling)
    void uploadFile(const QString& filePath, 
                    const std::string& uploadEndpoint,
                    const ProgressCallback& progressCallback = nullptr,
                    int maxRetries = 3);
    
    void downloadFile(const std::string& downloadEndpoint,
                      const QString& savePath,
                      const ProgressCallback& progressCallback = nullptr,
                      int maxRetries = 3);
    
    // Cancel ongoing transfer
    void cancelTransfer();

    // Performance tuning
    void setChunkSize(size_t size);
    void setOptimizedForLargeFiles(bool optimize); // Uses 256KB chunks
    void setOptimizedForNetwork(const std::string& connectionType); // "dialup", "broadband", "gigabit"

    // REPLACE: Change to async API (void return)
    void uploadFileAsync(const QString& filePath, 
                        const std::string& uploadEndpoint,
                        int maxRetries = 3);
    
    void downloadFileAsync(const std::string& downloadEndpoint,
                          const QString& savePath,
                          int maxRetries = 3);

signals:
    // NEW: Async results via signals
    void uploadCompleted(bool success, const TransferResult& result);
    void downloadCompleted(bool success, const TransferResult& result);
    void progressUpdated(qint64 bytesTransferred, qint64 totalBytes);
    void transferFailed(const QString& error);

private slots:
    void retryUpload();
    void retryDownload();

private:
    SSLContext& sslContext_;
    std::shared_ptr<HttpClient> httpClient_;
    std::string serverHost_;
    std::string serverPort_;
    QString authToken_;
    bool cancelRequested_;
    
    size_t chunkSize_{128 * 1024}; // Default 128KB
    
    // NEW: For async retries
    QTimer* retryTimer_;
    int currentAttempt_;
    int maxRetries_;
    QString currentFilePath_;
    std::string currentEndpoint_;
    QString currentSavePath_;
    
    // Helper methods
    HttpRequest createUploadRequest(const std::string& endpoint, const QString& filename, qint64 fileSize);
    HttpRequest createDownloadRequest(const std::string& endpoint);
    QString extractServerError(const HttpResponse& response);
    
    // NEW: Async implementations
    void performUploadAsync(const QString& filePath, const std::string& endpoint);
    void performDownloadAsync(const std::string& endpoint, const QString& savePath);
};

