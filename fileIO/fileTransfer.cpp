#include "fileTransfer.h"
#include <QMimeDatabase>
#include <QDir>
#include <QElapsedTimer>
#include <QThread>
#include <QLoggingCategory>
#include <QMetaType>
#include <iostream>
#include <iomanip>

Q_LOGGING_CATEGORY(fileTransfer, "fileTransfer") //uncomment if u dont want logging

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

FileTransfer::FileTransfer(SSLContext& sslContext, QObject* parent)
    : QObject(parent)
    , sslContext_(sslContext)
    , serverPort_("443")
    , cancelRequested_(false)
    , retryTimer_(new QTimer(this))
    , currentAttempt_(0)
    , maxRetries_(3)
{
    qRegisterMetaType<TransferResult>("TransferResult");
    
    // Setup retry timer
    retryTimer_->setSingleShot(true);
    connect(retryTimer_, &QTimer::timeout, this, &FileTransfer::retryUpload);
}

void FileTransfer::setServer(const std::string& host, const std::string& port) {
    serverHost_ = host;
    serverPort_ = port;
    httpClient_ = std::make_shared<HttpClient>(sslContext_, serverHost_, serverPort_);
}

void FileTransfer::setAuthToken(const QString& token) {
    authToken_ = token;
}

void FileTransfer::uploadFile(const QString& filePath,
                             const std::string& uploadEndpoint,
                             const ProgressCallback& progressCallback,
                             int maxRetries) {
    qCWarning(fileTransfer) << "uploadFile() is deprecated, use uploadFileAsync()";
    uploadFileAsync(filePath, uploadEndpoint, maxRetries);
}

void FileTransfer::downloadFile(const std::string& downloadEndpoint,
                               const QString& savePath,
                               const ProgressCallback& progressCallback,
                               int maxRetries) {
    qCWarning(fileTransfer) << "downloadFile() is deprecated, use downloadFileAsync()";
    downloadFileAsync(downloadEndpoint, savePath, maxRetries);
}

void FileTransfer::uploadFileAsync(const QString& filePath, 
                                  const std::string& uploadEndpoint,
                                  int maxRetries) {
    if (!httpClient_) {
        TransferResult result;
        result.errorMessage = "Server not configured. Call setServer() first.";
        emit uploadCompleted(false, result);
        return;
    }
    
    maxRetries_ = maxRetries;
    currentAttempt_ = 1;
    currentFilePath_ = filePath;
    currentEndpoint_ = uploadEndpoint;
    
    qCDebug(fileTransfer) << "Starting async upload:" << filePath;
    performUploadAsync(filePath, uploadEndpoint);
}

void FileTransfer::downloadFileAsync(const std::string& downloadEndpoint,
                                    const QString& savePath,
                                    int maxRetries) {
    if (!httpClient_) {
        TransferResult result;
        result.errorMessage = "Server not configured. Call setServer() first.";
        emit downloadCompleted(false, result);
        return;
    }
    
    maxRetries_ = maxRetries;
    currentAttempt_ = 1;
    currentEndpoint_ = downloadEndpoint;
    currentSavePath_ = savePath;
    
    qCDebug(fileTransfer) << "Starting async download to:" << savePath;
    performDownloadAsync(downloadEndpoint, savePath);
}

void FileTransfer::performUploadAsync(const QString& filePath, const std::string& endpoint) {
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        TransferResult result;
        result.errorMessage = "File not found: " + filePath;
        emit uploadCompleted(false, result);
        return;
    }
    
    qCDebug(fileTransfer) << "Upload attempt" << currentAttempt_ << "of" << maxRetries_;
    
    // Create request
    HttpRequest request = createUploadRequest(endpoint, fileInfo.fileName(), fileInfo.size());
    
    // ASYNC: Use sendAsync instead of blocking call
    httpClient_->sendAsync(request,
        // Success callback
        [this, filePath](const HttpResponse& response) {
            TransferResult result;
            if (response.statusCode == 200 && !cancelRequested_) {
                result.success = true;
                result.bytesTransferred = QFileInfo(filePath).size();
                result.serverResponse = QString::fromStdString(response.body);
                qCDebug(fileTransfer) << "Upload successful:" << result.bytesTransferred << "bytes";
                emit uploadCompleted(true, result);
            } else {
                result.errorMessage = cancelRequested_ ? 
                    QString("Upload cancelled") : 
                    extractServerError(response);
                
                // Retry or fail
                if (currentAttempt_ < maxRetries_ && !cancelRequested_) {
                    currentAttempt_++;
                    qCWarning(fileTransfer) << "Upload failed, retrying in" << currentAttempt_ << "seconds...";
                    
                    // FIX: Proper retry timer setup
                    disconnect(retryTimer_, nullptr, nullptr, nullptr);
                    connect(retryTimer_, &QTimer::timeout, this, &FileTransfer::retryUpload);
                    retryTimer_->start(currentAttempt_ * 1000);
                } else {
                    qCCritical(fileTransfer) << "Upload failed after" << maxRetries_ << "attempts";
                    emit uploadCompleted(false, result);
                }
            }
        },
        // Error callback
        [this](const QString& error) {
            if (currentAttempt_ < maxRetries_ && !cancelRequested_) {
                currentAttempt_++;
                qCWarning(fileTransfer) << "Upload error, retrying in" << currentAttempt_ << "seconds:" << error;
                
                // FIX: Proper retry timer setup  
                disconnect(retryTimer_, nullptr, nullptr, nullptr);
                connect(retryTimer_, &QTimer::timeout, this, &FileTransfer::retryUpload);
                retryTimer_->start(currentAttempt_ * 1000);
            } else {
                TransferResult result;
                result.errorMessage = "Upload failed after " + QString::number(maxRetries_) + " attempts: " + error;
                qCCritical(fileTransfer) << result.errorMessage;
                emit uploadCompleted(false, result);
            }
        });
}

void FileTransfer::performDownloadAsync(const std::string& endpoint, const QString& savePath) {
    // Create directory if needed
    QFileInfo saveInfo(savePath);
    QDir saveDir = saveInfo.absoluteDir();
    if (!saveDir.exists()) {
        saveDir.mkpath(".");
    }
    
    qCDebug(fileTransfer) << "Download attempt" << currentAttempt_ << "of" << maxRetries_;
    
    // Create request
    HttpRequest request = createDownloadRequest(endpoint);
    
    // ASYNC: Use sendAsync instead of blocking call  
    httpClient_->sendAsync(request,
        // Success callback
        [this, savePath](const HttpResponse& response) {
            TransferResult result;
            if (response.statusCode == 200 && !cancelRequested_) {
                // Write response to file
                QFile file(savePath);
                if (file.open(QIODevice::WriteOnly)) {
                    file.write(response.body.c_str(), response.body.size());
                    result.success = true;
                    result.bytesTransferred = file.size();
                    qCDebug(fileTransfer) << "Download successful:" << result.bytesTransferred << "bytes";
                    emit downloadCompleted(true, result);
                } else {
                    result.errorMessage = "Cannot create file: " + file.errorString();
                    qCCritical(fileTransfer) << result.errorMessage;
                    emit downloadCompleted(false, result);
                }
            } else {
                result.errorMessage = cancelRequested_ ? 
                    QString("Download cancelled") : 
                    extractServerError(response);
                
                // Retry or fail
                if (currentAttempt_ < maxRetries_ && !cancelRequested_) {
                    currentAttempt_++;
                    qCWarning(fileTransfer) << "Download failed, retrying in" << currentAttempt_ << "seconds...";
                    
                    // FIX: Proper retry timer setup
                    disconnect(retryTimer_, nullptr, nullptr, nullptr);
                    connect(retryTimer_, &QTimer::timeout, this, &FileTransfer::retryDownload);
                    retryTimer_->start(currentAttempt_ * 1000);
                } else {
                    qCCritical(fileTransfer) << "Download failed after" << maxRetries_ << "attempts";
                    QFile::remove(savePath);
                    emit downloadCompleted(false, result);
                }
            }
        },
        // Error callback
        [this, savePath](const QString& error) {
            if (currentAttempt_ < maxRetries_ && !cancelRequested_) {
                currentAttempt_++;
                qCWarning(fileTransfer) << "Download error, retrying in" << currentAttempt_ << "seconds:" << error;
                
                // FIX: Proper retry timer setup
                disconnect(retryTimer_, nullptr, nullptr, nullptr);
                connect(retryTimer_, &QTimer::timeout, this, &FileTransfer::retryDownload);
                retryTimer_->start(currentAttempt_ * 1000);
            } else {
                TransferResult result;
                result.errorMessage = "Download failed after " + QString::number(maxRetries_) + " attempts: " + error;
                qCCritical(fileTransfer) << result.errorMessage;
                QFile::remove(savePath);
                emit downloadCompleted(false, result);
            }
        });
}

void FileTransfer::retryUpload() {
    performUploadAsync(currentFilePath_, currentEndpoint_);
}

void FileTransfer::retryDownload() {
    performDownloadAsync(currentEndpoint_, currentSavePath_);
}

void FileTransfer::cancelTransfer() {
    cancelRequested_ = true;
    retryTimer_->stop();
    qCWarning(fileTransfer) << "Transfer cancelled by user";
}

void FileTransfer::setChunkSize(size_t size) {
    chunkSize_ = size;
    qCDebug(fileTransfer) << "Chunk size set to:" << size;
}

void FileTransfer::setOptimizedForLargeFiles(bool optimize) {
    if (optimize) {
        setChunkSize(256 * 1024); // 256KB chunks
        qCDebug(fileTransfer) << "Optimized for large files";
    }
}

void FileTransfer::setOptimizedForNetwork(const std::string& connectionType) {
    if (connectionType == "dialup") {
        setChunkSize(8 * 1024);  // 8KB
    } else if (connectionType == "broadband") {
        setChunkSize(128 * 1024); // 128KB  
    } else if (connectionType == "gigabit") {
        setChunkSize(1024 * 1024); // 1MB
    }
    qCDebug(fileTransfer) << "Optimized for" << connectionType.c_str() << "connection";
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

QString FileTransfer::extractServerError(const HttpResponse& response) {
    QString error = "HTTP " + QString::number(response.statusCode) + ": " + QString::fromStdString(response.statusMessage);
    
    if (!response.body.empty()) {
        error += " - " + QString::fromStdString(response.body);
    }
    
    return error;
} 