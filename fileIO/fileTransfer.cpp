#include "fileTransfer.h"
#include <QMimeDatabase>
#include <QDir>
#include <QElapsedTimer>
#include <QThread>
#include <QMetaType>
#include <QtConcurrent>
#include <QDateTime>
#include <sstream>
#include "../utils/Config.h"  // Add Config include for server details
#include <iostream>

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
    , cancelRequested_(false)
    , retryTimer_(new QTimer(this))
    , currentAttempt_(0)
    , maxRetries_(3)
{
    qRegisterMetaType<TransferResult>("TransferResult");
    
    std::cout << "🔧 FILETRANSFER: Constructor called - maxRetries set to " << maxRetries_ << std::endl;
    
    // Setup retry timer
    retryTimer_->setSingleShot(true);
    connect(retryTimer_, &QTimer::timeout, this, &FileTransfer::retryUpload);
}

void FileTransfer::setHttpClient(std::shared_ptr<HttpClient> httpClient) {
    httpClient_ = httpClient;
    std::cout << "🔧 FILETRANSFER: HttpClient set - " << (httpClient_ ? "SUCCESS" : "FAILED") << std::endl;
}

void FileTransfer::setAuthToken(const QString& token) {
    authToken_ = token;
    std::cout << "🔧 FILETRANSFER: Auth token set - " << token.left(20) << "..." << std::endl;
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

void FileTransfer::uploadFileAsync(const QString& filePath, 
                                  const std::string& uploadEndpoint,
                                  int maxRetries) {
    std::cout << "🚀 FILETRANSFER: uploadFileAsync called!" << std::endl;
    std::cout << "   📁 File: " << filePath.toStdString() << std::endl;
    std::cout << "   🎯 Endpoint: " << uploadEndpoint << std::endl;
    std::cout << "   🔄 Max retries: " << maxRetries << std::endl;
    
    if (!httpClient_) {
        std::cout << "❌ FILETRANSFER: HttpClient not configured!" << std::endl;
        TransferResult result;
        result.errorMessage = "HttpClient not configured. Call setHttpClient() first.";
        emit uploadCompleted(false, result);
        return;
    }
    
    maxRetries_ = maxRetries;
    currentAttempt_ = 1;
    currentFilePath_ = filePath;
    currentEndpoint_ = uploadEndpoint;
    
    std::cout << "✅ FILETRANSFER: Starting upload attempt #" << currentAttempt_ << std::endl;
    performUploadAsync(filePath, uploadEndpoint);
}

void FileTransfer::downloadFileAsync(const std::string& downloadEndpoint,
                                    const QString& savePath,
                                    int maxRetries) {
    if (!httpClient_) {
        TransferResult result;
        result.errorMessage = "HttpClient not configured. Call setHttpClient() first.";
        emit downloadCompleted(false, result);
        return;
    }
    
    maxRetries_ = maxRetries;
    currentAttempt_ = 1;
    currentEndpoint_ = downloadEndpoint;
    currentSavePath_ = savePath;
    
    performDownloadAsync(downloadEndpoint, savePath);
}

void FileTransfer::performUploadAsync(const QString& filePath, const std::string& endpoint) {
    std::cout << "📤 FILETRANSFER: performUploadAsync called - attempt #" << currentAttempt_ << std::endl;
    
    // Validate file
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        std::cout << "❌ FILETRANSFER: File validation failed: " << filePath.toStdString() << std::endl;
        TransferResult result;
        result.errorMessage = "File not found: " + filePath;
        emit uploadCompleted(false, result);
        return;
    }
    
    std::cout << "📋 FILETRANSFER: File info - Size: " << fileInfo.size() << " bytes, Name: " << fileInfo.fileName().toStdString() << std::endl;
    
    // Create request WITHOUT body (we'll build multipart body separately)
    HttpRequest request = createUploadRequest(endpoint, fileInfo.fileName(), fileInfo.size());
    std::cout << "📝 FILETRANSFER: HTTP request created - Method: " << request.method << ", Path: " << request.path << std::endl;
    std::cout << "📝 FILETRANSFER: Content-Type: " << request.headers["Content-Type"] << std::endl;
    
    // Use QtConcurrent for async operation
    auto self = shared_from_this();
    auto future = QtConcurrent::run([self, request, filePath, fileInfo]() mutable {
        std::cout << "🧵 FILETRANSFER: Background thread started for upload" << std::endl;
        try {
            // 🔥 NEW: Build multipart form data body (not streaming)
            std::cout << "🔧 FILETRANSFER: Building multipart form data..." << std::endl;
            std::string multipartBody = self->buildMultipartFormData(filePath, fileInfo.fileName());
            request.body = multipartBody;
            
            std::cout << "📦 FILETRANSFER: Multipart body built - Size: " << multipartBody.size() << " bytes" << std::endl;
            std::cout << "📡 FILETRANSFER: Calling httpClient_->sendRequest (NOT streaming)..." << std::endl;
            
            // Use regular sendRequest instead of sendRequestWithStreamingBody
            HttpResponse response = self->httpClient_->sendRequest(request);
            std::cout << "📥 FILETRANSFER: Got response - Status: " << response.statusCode << ", Message: " << response.statusMessage << std::endl;
            std::cout << "📄 FILETRANSFER: Response body length: " << response.body.length() << std::endl;
            
            // Back to GUI thread
            QMetaObject::invokeMethod(qApp, [self, response, filePath]() {
                std::cout << "🖥️ FILETRANSFER: Back on GUI thread - processing response" << std::endl;
                TransferResult result;
                if (response.statusCode == 200 && !self->cancelRequested_) {
                    std::cout << "✅ FILETRANSFER: Upload SUCCESS!" << std::endl;
                    result.success = true;
                    result.bytesTransferred = QFileInfo(filePath).size();
                    result.serverResponse = QString::fromStdString(response.body);
                    emit self->uploadCompleted(true, result);
                } else {
                    std::cout << "❌ FILETRANSFER: Upload FAILED - Status: " << response.statusCode << ", Cancelled: " << self->cancelRequested_ << std::endl;
                    result.errorMessage = self->cancelRequested_ ? 
                        QString("Upload cancelled") : 
                        self->extractServerError(response);
                    
                    std::cout << "🔄 FILETRANSFER: Checking retry logic - attempt " << self->currentAttempt_ << "/" << self->maxRetries_ << std::endl;
                    
                    // Retry logic
                    if (self->currentAttempt_ < self->maxRetries_ && !self->cancelRequested_) {
                        self->currentAttempt_++;
                        std::cout << "🔁 FILETRANSFER: Scheduling retry #" << self->currentAttempt_ << " in " << (self->currentAttempt_ * 1000) << "ms" << std::endl;
                        disconnect(self->retryTimer_, nullptr, nullptr, nullptr);
                        connect(self->retryTimer_, &QTimer::timeout, self.get(), &FileTransfer::retryUpload);
                        self->retryTimer_->start(self->currentAttempt_ * 1000);
                    } else {
                        std::cout << "💀 FILETRANSFER: Max retries exceeded or cancelled - giving up" << std::endl;
                        emit self->uploadCompleted(false, result);
                    }
                }
            }, Qt::QueuedConnection);
            
        } catch (const std::exception& e) {
            std::cout << "💥 FILETRANSFER: Exception in background thread: " << e.what() << std::endl;
            // Back to GUI thread for error
            QMetaObject::invokeMethod(qApp, [self, e]() {
                std::cout << "🖥️ FILETRANSFER: Exception handling on GUI thread" << std::endl;
                if (self->currentAttempt_ < self->maxRetries_ && !self->cancelRequested_) {
                    self->currentAttempt_++;
                    std::cout << "🔁 FILETRANSFER: Exception retry #" << self->currentAttempt_ << " in " << (self->currentAttempt_ * 1000) << "ms" << std::endl;
                    disconnect(self->retryTimer_, nullptr, nullptr, nullptr);
                    connect(self->retryTimer_, &QTimer::timeout, self.get(), &FileTransfer::retryUpload);
                    self->retryTimer_->start(self->currentAttempt_ * 1000);
                } else {
                    std::cout << "💀 FILETRANSFER: Exception - max retries exceeded" << std::endl;
                    TransferResult result;
                    result.errorMessage = "Upload failed: " + QString::fromStdString(e.what());
                    emit self->uploadCompleted(false, result);
                }
            }, Qt::QueuedConnection);
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
    
    // Create request
    HttpRequest request = createDownloadRequest(endpoint);
    
    // Use QtConcurrent for proper async streaming (like upload does)
    auto self = shared_from_this();
    auto future = QtConcurrent::run([self, request, savePath, endpoint]() {
        try {
            // Create output file with progress tracking
            QFile file(savePath);
            if (!file.open(QIODevice::WriteOnly)) {
                QMetaObject::invokeMethod(qApp, [self, savePath]() {
                    TransferResult result;
                    result.errorMessage = "Cannot create file: " + savePath;
                    emit self->downloadCompleted(false, result);
                }, Qt::QueuedConnection);
                return;
            }
            
            // Use STREAMING download (not buffered sendAsync)
            bool success = self->httpClient_->downloadToStreamWithProgress(request, file,
                [self](qint64 downloaded, qint64 total) -> bool {
                    emit self->progressUpdated(downloaded, total);
                    return !self->cancelRequested_;
                });
            qint64 bytesDownloaded = file.size();
            file.close();
            
            // Back to GUI thread with result
            QMetaObject::invokeMethod(qApp, [self, success, bytesDownloaded, savePath]() {
                TransferResult result;
                if (success && !self->cancelRequested_) {
                    result.success = true;
                    result.bytesTransferred = bytesDownloaded;
                    emit self->downloadCompleted(true, result);
                } else {
                    result.errorMessage = self->cancelRequested_ ? 
                        QString("Download cancelled") : 
                        QString("Download failed - server error or connection issue");
                    
                    // Retry logic
                    if (self->currentAttempt_ < self->maxRetries_ && !self->cancelRequested_) {
                        self->currentAttempt_++;
                        
                        disconnect(self->retryTimer_, nullptr, nullptr, nullptr);
                        connect(self->retryTimer_, &QTimer::timeout, self.get(), &FileTransfer::retryDownload);
                        self->retryTimer_->start(self->currentAttempt_ * 1000);
                    } else {
                        QFile::remove(savePath);
                        emit self->downloadCompleted(false, result);
                    }
                }
            }, Qt::QueuedConnection);
            
        } catch (const std::exception& e) {
            // Back to GUI thread for error
            QMetaObject::invokeMethod(qApp, [self, e, savePath]() {
                if (self->currentAttempt_ < self->maxRetries_ && !self->cancelRequested_) {
                    self->currentAttempt_++;
                    
                    disconnect(self->retryTimer_, nullptr, nullptr, nullptr);
                    connect(self->retryTimer_, &QTimer::timeout, self.get(), &FileTransfer::retryDownload);
                    self->retryTimer_->start(self->currentAttempt_ * 1000);
                } else {
                    TransferResult result;
                    result.errorMessage = "Download failed after " + QString::number(self->maxRetries_) + " attempts: " + QString::fromStdString(e.what());
                    QFile::remove(savePath);
                    emit self->downloadCompleted(false, result);
                }
            }, Qt::QueuedConnection);
        }
    });
}

void FileTransfer::retryUpload() {
    std::cout << "🔁 FILETRANSFER: retryUpload called - attempt #" << currentAttempt_ << std::endl;
    performUploadAsync(currentFilePath_, currentEndpoint_);
}

void FileTransfer::retryDownload() {
    performDownloadAsync(currentEndpoint_, currentSavePath_);
}

void FileTransfer::cancelTransfer() {
    cancelRequested_ = true;
    retryTimer_->stop();
}

void FileTransfer::setChunkSize(size_t size) {
    chunkSize_ = size;
}

void FileTransfer::setOptimizedForLargeFiles(bool optimize) {
    if (optimize) {
        setChunkSize(256 * 1024); // 256KB chunks
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
}

HttpRequest FileTransfer::createUploadRequest(const std::string& endpoint, 
                                            const QString& filename, 
                                            qint64 fileSize) {
    HttpRequest request;
    request.method = "POST";
    request.path = endpoint;
    request.headers["Host"] = Config::getInstance().getServerHost().toStdString();
    request.headers["User-Agent"] = "ChrisPlusPlus-FileTransfer/1.0";
    
    // 🔥 CRITICAL FIX: Use multipart/form-data instead of octet-stream
    // Generate boundary for multipart form data
    std::string boundary = "----ChrisPlusPlus" + std::to_string(QDateTime::currentMSecsSinceEpoch());
    request.headers["Content-Type"] = "multipart/form-data; boundary=" + boundary;
    
    // ❌ REMOVED: These headers are wrong for multipart uploads
    // request.headers["Content-Type"] = "application/octet-stream";
    // request.headers["Transfer-Encoding"] = "chunked";
    // request.headers["X-File-Name"] = filename.toStdString();
    // request.headers["X-File-Size"] = std::to_string(fileSize);
    
    if (!authToken_.isEmpty()) {
        request.headers["Authorization"] = ("Bearer " + authToken_).toStdString();
    }
    
    std::cout << "📝 FILETRANSFER: Created multipart request with boundary: " << boundary << std::endl;
    
    // Store boundary for later use in building the multipart body
    boundary_ = boundary;
    filename_ = filename;
    
    return request;
}

HttpRequest FileTransfer::createDownloadRequest(const std::string& endpoint) {
    HttpRequest request;
    request.method = "GET";
    request.path = endpoint;
    request.headers["Host"] = Config::getInstance().getServerHost().toStdString();
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

QString FileTransfer::sanitizePath(const QString& path) const {
    QFileInfo fileInfo(path);
    QString absolutePath = fileInfo.absoluteFilePath();
    return QDir::cleanPath(absolutePath);
}

bool FileTransfer::isPathSafe(const QString& basePath, const QString& targetPath) const {
    QString cleanBase = QDir::cleanPath(QDir(basePath).absolutePath());
    QString cleanTarget = QDir::cleanPath(QDir(targetPath).absolutePath());
    return cleanTarget.startsWith(cleanBase);
}

// NEW: Build multipart form data for file uploads
std::string FileTransfer::buildMultipartFormData(const QString& filePath, const QString& filename) {
    std::cout << "🔧 FILETRANSFER: Building multipart form data for: " << filename.toStdString() << std::endl;
    
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        throw std::runtime_error("Cannot open file for reading: " + file.errorString().toStdString());
    }
    
    QByteArray fileData = file.readAll();
    file.close();
    
    std::cout << "📁 FILETRANSFER: Read file data - Size: " << fileData.size() << " bytes" << std::endl;
    
    std::stringstream formData;
    
    // Add file field (the main file data)
    formData << "--" << boundary_ << "\r\n";
    formData << "Content-Disposition: form-data; name=\"file\"; filename=\"" << filename.toStdString() << "\"\r\n";
    formData << "Content-Type: application/octet-stream\r\n\r\n";
    
    // Write file data
    formData.write(fileData.constData(), fileData.size());
    formData << "\r\n";
    
    // Add filename field (for server processing)
    formData << "--" << boundary_ << "\r\n";
    formData << "Content-Disposition: form-data; name=\"filename\"\r\n\r\n";
    formData << filename.toStdString() << "\r\n";
    
    // End boundary
    formData << "--" << boundary_ << "--\r\n";
    
    std::string result = formData.str();
    std::cout << "✅ FILETRANSFER: Multipart form data built - Total size: " << result.size() << " bytes" << std::endl;
    
    return result;
} 