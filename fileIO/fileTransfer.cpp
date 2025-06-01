#include "fileTransfer.h"
#include <QMimeDatabase>
#include <QDir>
#include <QElapsedTimer>
#include <QThread>
#include <QLoggingCategory>
#include <iostream>
#include <iomanip>

Q_LOGGING_CATEGORY(fileTransfer, "fileTransfer")

// Simple progress tracking wrapper
class ProgressTrackingFile : public QFile {
public:
    ProgressTrackingFile(const QString& fileName, const ProgressCallback& callback)
        : QFile(fileName), callback_(callback), bytesRead_(0) {}

protected:
    qint64 readData(char* data, qint64 maxlen) override {
        qint64 read = QFile::readData(data, maxlen);
        if (read > 0) {
            bytesRead_ += read;
            if (callback_) {
                if (!callback_(bytesRead_, size())) {
                    return -1; // Signal cancellation
                }
            }
        }
        return read;
    }

private:
    ProgressCallback callback_;
    qint64 bytesRead_;
};

FileTransfer::FileTransfer(SSLContext& sslContext)
    : sslContext_(sslContext)
    , serverPort_("443")
    , cancelRequested_(false)
{
}

void FileTransfer::setServer(const std::string& host, const std::string& port) {
    serverHost_ = host;
    serverPort_ = port;
    httpClient_ = std::make_unique<HttpClient>(sslContext_, serverHost_, serverPort_);
}

void FileTransfer::setAuthToken(const QString& token) {
    authToken_ = token;
}

void FileTransfer::setAllowedMimeTypes(const QSet<QString>& mimeTypes) {
    allowedMimeTypes_ = mimeTypes;
}

void FileTransfer::setMaxFileSize(qint64 maxSize) {
    maxFileSize_ = maxSize;
}

bool FileTransfer::isFileTypeAllowed(const QString& filePath) const {
    if (allowedMimeTypes_.isEmpty()) {
        return true; // No restrictions if no mime types are set
    }

    QMimeType mimeType = mimeDb_.mimeTypeForFile(filePath);
    return allowedMimeTypes_.contains(mimeType.name());
}

bool FileTransfer::isFileSizeAllowed(qint64 size) const {
    return size <= maxFileSize_;
}

TransferResult FileTransfer::uploadFile(const QString& filePath,
                                      const std::string& uploadEndpoint,
                                      const ProgressCallback& progressCallback,
                                      int maxRetries) {
    if (!httpClient_) {
        TransferResult result;
        result.errorMessage = "Server not configured. Call setServer() first.";
        return result;
    }
    
    return performUploadWithRetry(filePath, uploadEndpoint, progressCallback, maxRetries);
}

TransferResult FileTransfer::downloadFile(const std::string& downloadEndpoint,
                                        const QString& savePath,
                                        const ProgressCallback& progressCallback,
                                        int maxRetries) {
    if (!httpClient_) {
        TransferResult result;
        result.errorMessage = "Server not configured. Call setServer() first.";
        return result;
    }
    
    return performDownloadWithRetry(downloadEndpoint, savePath, progressCallback, maxRetries);
}

TransferResult FileTransfer::performUploadWithRetry(const QString& filePath,
                                                  const std::string& endpoint,
                                                  const ProgressCallback& callback,
                                                  int maxRetries) {
    TransferResult lastResult;
    
    // Get file info
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        lastResult.errorMessage = "File not found: " + filePath;
        return lastResult;
    }

    // Validate file size
    if (!isFileSizeAllowed(fileInfo.size())) {
        lastResult.errorMessage = QString("File size exceeds maximum allowed size of %1 bytes").arg(maxFileSize_);
        return lastResult;
    }

    // Validate file type
    if (!isFileTypeAllowed(filePath)) {
        lastResult.errorMessage = "File type not allowed";
        return lastResult;
    }
    
    for (int attempt = 1; attempt <= maxRetries; ++attempt) {
        std::cout << "Upload attempt " << attempt << " of " << maxRetries << std::endl;
        
        try {
            cancelRequested_ = false;
            
            // Create progress tracking file wrapper
            ProgressTrackingFile progressFile(filePath, callback);
            if (!progressFile.open(QIODevice::ReadOnly)) {
                lastResult.errorMessage = "Cannot open file: " + progressFile.errorString();
                continue;
            }
            
            // Create request
            HttpRequest request = createUploadRequest(endpoint, fileInfo.fileName(), fileInfo.size());
            
            // Add MIME type header
            QMimeType mimeType = mimeDb_.mimeTypeForFile(filePath);
            request.headers["Content-Type"] = mimeType.name().toStdString();
            
            // Upload using your existing streaming method
            HttpResponse response = httpClient_->sendRequestWithStreamingBody(request, progressFile);
            
            if (response.statusCode == 200 && !cancelRequested_) {
                lastResult.success = true;
                lastResult.bytesTransferred = progressFile.size();
                lastResult.serverResponse = QString::fromStdString(response.body);
                std::cout << "Upload successful: " << lastResult.bytesTransferred << " bytes" << std::endl;
                return lastResult;
            } else {
                lastResult.errorMessage = cancelRequested_ ? 
                    QString("Upload cancelled") : 
                    extractServerError(response);
            }
            
        } catch (const std::exception& e) {
            lastResult.errorMessage = "Upload error: " + QString::fromStdString(e.what());
        }
        
        if (attempt < maxRetries) {
            std::cout << "Upload failed, retrying in " << attempt << " seconds..." << std::endl;
            QThread::msleep(attempt * 1000);
        }
    }
    
    lastResult.errorMessage = "Upload failed after " + QString::number(maxRetries) + " attempts: " + lastResult.errorMessage;
    return lastResult;
}

QString sanitizePath(const QString& path) {
    // Convert to absolute and canonical path
    QFileInfo fileInfo(path);
    QString absolutePath = fileInfo.absoluteFilePath();
    return QDir::cleanPath(absolutePath);
}

bool isPathSafe(const QString& basePath, const QString& targetPath) {
    QString cleanBase = QDir::cleanPath(QDir(basePath).absolutePath());
    QString cleanTarget = QDir::cleanPath(QDir(targetPath).absolutePath());
    return cleanTarget.startsWith(cleanBase);
}

TransferResult FileTransfer::performDownloadWithRetry(const std::string& endpoint,
                                                    const QString& savePath,
                                                    const ProgressCallback& callback,
                                                    int maxRetries) {
    TransferResult lastResult;
    QString sanitizedPath;  
    
    for (int attempt = 1; attempt <= maxRetries; ++attempt) {
        std::cout << "Download attempt " << attempt << " of " << maxRetries << std::endl;
        
        try {
            cancelRequested_ = false;
            
            // Sanitize and validate save path
            sanitizedPath = sanitizePath(savePath);  
            QString baseDir = QDir::cleanPath(QDir::currentPath());
            
            if (!isPathSafe(baseDir, sanitizedPath)) {
                lastResult.errorMessage = "Invalid save path: Path traversal detected";
                return lastResult;
            }
            
            // Create directory if needed
            QFileInfo saveInfo(sanitizedPath);
            QDir saveDir = saveInfo.absoluteDir();
            if (!saveDir.exists()) {
                if (!saveDir.mkpath(".")) {
                    lastResult.errorMessage = "Failed to create directory structure";
                    return lastResult;
                }
            }
            
            // Open file for writing
            QFile file(sanitizedPath);
            if (!file.open(QIODevice::WriteOnly)) {
                lastResult.errorMessage = "Cannot create file: " + file.errorString();
                continue;
            }
            
            // Create request
            HttpRequest request = createDownloadRequest(endpoint);
            
            // Download using your existing streaming method
            bool success = httpClient_->downloadToStream(request, file);
            
            if (success && !cancelRequested_) {
                lastResult.success = true;
                lastResult.bytesTransferred = file.size();
                std::cout << "Download successful: " << lastResult.bytesTransferred << " bytes" << std::endl;
                
                if (callback) {
                    callback(lastResult.bytesTransferred, lastResult.bytesTransferred);
                }
                
                return lastResult;
            } else {
                lastResult.errorMessage = cancelRequested_ ? 
                    QString("Download cancelled") : 
                    QString("Download failed");
                QFile::remove(sanitizedPath);
            }
            
        } catch (const std::exception& e) {
            lastResult.errorMessage = "Download error: " + QString::fromStdString(e.what());
            QFile::remove(sanitizedPath);
        }
        
        if (attempt < maxRetries) {
            std::cout << "Download failed, retrying in " << attempt << " seconds..." << std::endl;
            QThread::msleep(attempt * 1000);
        }
    }
    
    lastResult.errorMessage = "Download failed after " + QString::number(maxRetries) + " attempts: " + lastResult.errorMessage;
    return lastResult;
}

HttpRequest FileTransfer::createUploadRequest(const std::string& endpoint, 
                                            const QString& filename, 
                                            qint64 fileSize) {
    HttpRequest request;
    request.method = "POST";
    request.path = endpoint;
    request.headers["Host"] = serverHost_;
    request.headers["User-Agent"] = "ChrisPlusPlus-FileTransfer/1.0";
    request.headers["Content-Type"] = "application/octet-stream";
    request.headers["Transfer-Encoding"] = "chunked";
    request.headers["X-File-Name"] = filename.toStdString();
    request.headers["X-File-Size"] = std::to_string(fileSize);
    
    if (!authToken_.isEmpty()) {
        request.headers["Authorization"] = ("Bearer " + authToken_).toStdString();
    }
    
    return request;
}

HttpRequest FileTransfer::createDownloadRequest(const std::string& endpoint) {
    HttpRequest request;
    request.method = "GET";
    request.path = endpoint;
    request.headers["Host"] = serverHost_;
    request.headers["User-Agent"] = "ChrisPlusPlus-FileTransfer/1.0";
    request.headers["Accept"] = "*/*";
    
    if (!authToken_.isEmpty()) {
        request.headers["Authorization"] = ("Bearer " + authToken_).toStdString();
    }
    
    return request;
}

void FileTransfer::cancelTransfer() {
    cancelRequested_ = true;
}

QString FileTransfer::extractServerError(const HttpResponse& response) {
    // Simple concatenation instead of .arg()
    QString error = "HTTP " + QString::number(response.statusCode) + ": " + QString::fromStdString(response.statusMessage);
    
    if (!response.body.empty()) {
        error += " - " + QString::fromStdString(response.body);
    }
    
    return error;
} 