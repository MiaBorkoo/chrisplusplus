#pragma once

#include "../httpC/HttpClient.h"
#include "../sockets/SSLContext.h"
#include <QObject>
#include <QTimer>
#include <QFile>
#include <QFileInfo>
#include <QString>
#include <QMimeDatabase>
#include <QSet>
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

// CHANGE: Make it inherit from QObject and std::enable_shared_from_this
class FileTransfer : public QObject, public std::enable_shared_from_this<FileTransfer> {
    Q_OBJECT
    
public:
    explicit FileTransfer(SSLContext& sslContext, QObject* parent = nullptr);
    ~FileTransfer() = default;

    // Use shared HttpClient from Client for same connection
    void setHttpClient(std::shared_ptr<HttpClient> httpClient);
    
    // Authentication (sets token for requests)
    void setAuthToken(const QString& token);
    
    // File type validation
    void setAllowedMimeTypes(const QSet<QString>& mimeTypes);
    void setMaxFileSize(qint64 maxSize);
    bool isFileTypeAllowed(const QString& filePath) const;
    bool isFileSizeAllowed(qint64 size) const;
    
    // Main operations (with built-in retry and error handling)
    void uploadFileAsync(const QString& filePath, 
                        const std::string& uploadEndpoint,
                        int maxRetries = 3);
    
    // Cancel ongoing transfer
    void cancelTransfer();

    // Performance tuning
    void setChunkSize(size_t size);
    void setOptimizedForLargeFiles(bool optimize); // Uses 256KB chunks
    void setOptimizedForNetwork(const std::string& connectionType); // "dialup", "broadband", "gigabit"

    
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
    QString authToken_;
    bool cancelRequested_;
    
    size_t chunkSize_{128 * 1024}; // Default 128KB
    QSet<QString> allowedMimeTypes_;
    qint64 maxFileSize_{100 * 1024 * 1024}; // Default 100MB
    QMimeDatabase mimeDb_;
    
    // NEW: For async retries
    QTimer* retryTimer_;
    int currentAttempt_;
    int maxRetries_;
    QString currentFilePath_;
    std::string currentEndpoint_;
    QString currentSavePath_;
    
    // NEW: For multipart form data
    std::string boundary_;
    std::string filename_;
    
    // Helper methods
    HttpRequest createUploadRequest(const std::string& endpoint, const QString& filename, qint64 fileSize);
    HttpRequest createDownloadRequest(const std::string& endpoint);
    QString extractServerError(const HttpResponse& response);
    QString sanitizePath(const QString& path) const;
    bool isPathSafe(const QString& basePath, const QString& targetPath) const;
    
    // NEW: Multipart form data builder
    std::string buildMultipartFormData(const QString& filePath, const std::string& filename);
    
    // NEW: Async implementations
    void performUploadAsync(const QString& filePath, const std::string& endpoint);
    void performDownloadAsync(const std::string& endpoint, const QString& savePath);
};

