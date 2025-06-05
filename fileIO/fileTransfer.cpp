#include "fileTransfer.h"
#include <QMimeDatabase>
#include <QDir>
#include <QElapsedTimer>
#include <QThread>
#include <QMetaType>
#include <QtConcurrent>
#include <QDateTime>
#include <sstream>
#include <iostream>
#include "../utils/Config.h"  // Add Config include for server details

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
    
    // Setup retry timer
    retryTimer_->setSingleShot(true);
    connect(retryTimer_, &QTimer::timeout, this, &FileTransfer::retryUpload);
}

void FileTransfer::setHttpClient(std::shared_ptr<HttpClient> httpClient) {
    httpClient_ = httpClient;
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

void FileTransfer::uploadFileAsync(const QString& filePath, 
                                  const std::string& uploadEndpoint,
                                  int maxRetries) {
    maxRetries_ = maxRetries;
    currentAttempt_ = 1;
    currentFilePath_ = filePath;
    currentEndpoint_ = uploadEndpoint;
    
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
    // Validate file
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        TransferResult result;
        result.errorMessage = "File not found: " + filePath;
        emit uploadCompleted(false, result);
        return;
    }
    
    // Create request WITHOUT body (we'll build multipart body separately)
    HttpRequest request = createUploadRequest(endpoint, fileInfo.fileName(), fileInfo.size());
    
    // Use QtConcurrent for async operation
    auto self = shared_from_this();
    auto future = QtConcurrent::run([self, request, filePath, fileInfo]() mutable {
        try {
            // 🔥 NEW: Build multipart form data body (not streaming)
            std::string multipartBody = self->buildMultipartFormData(filePath, fileInfo.fileName().toStdString());
            request.body = multipartBody;
            
            std::cout << "📡 FILETRANSFER: Sending multipart request to " << request.path << std::endl;
            std::cout << "📦 FILETRANSFER: Request body size: " << multipartBody.size() << " bytes" << std::endl;
            
            // Use regular sendRequest instead of sendRequestWithStreamingBody
            HttpResponse response = self->httpClient_->sendRequest(request);
            
            // Back to GUI thread
            QMetaObject::invokeMethod(qApp, [self, response, filePath]() {
                TransferResult result;
                if (response.statusCode == 200 && !self->cancelRequested_) {
                    result.success = true;
                    result.bytesTransferred = QFileInfo(filePath).size();
                    result.serverResponse = QString::fromStdString(response.body);
                    emit self->uploadCompleted(true, result);
                } else {
                    result.errorMessage = self->cancelRequested_ ? 
                        QString("Upload cancelled") : 
                        self->extractServerError(response);
                    
                    // Retry logic
                    if (self->currentAttempt_ < self->maxRetries_ && !self->cancelRequested_) {
                        self->currentAttempt_++;
                        disconnect(self->retryTimer_, nullptr, nullptr, nullptr);
                        connect(self->retryTimer_, &QTimer::timeout, self.get(), &FileTransfer::retryUpload);
                        self->retryTimer_->start(self->currentAttempt_ * 1000);
                    } else {
                        emit self->uploadCompleted(false, result);
                    }
                }
            }, Qt::QueuedConnection);
            
        } catch (const std::exception& e) {
            // Back to GUI thread for error
            QMetaObject::invokeMethod(qApp, [self, e]() {
                if (self->currentAttempt_ < self->maxRetries_ && !self->cancelRequested_) {
                    self->currentAttempt_++;
                    disconnect(self->retryTimer_, nullptr, nullptr, nullptr);
                    connect(self->retryTimer_, &QTimer::timeout, self.get(), &FileTransfer::retryUpload);
                    self->retryTimer_->start(self->currentAttempt_ * 1000);
                } else {
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
    
    if (!authToken_.isEmpty()) {
        request.headers["Authorization"] = ("Bearer " + authToken_).toStdString();
    }
    
    // Store boundary for later use in building the multipart body
    boundary_ = boundary;
    filename_ = filename.toStdString();  // FIX: Convert to std::string immediately
    
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
std::string FileTransfer::buildMultipartFormData(const QString& filePath, const std::string& filename) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        throw std::runtime_error("Cannot open file for reading: " + file.errorString().toStdString());
    }
    
    QByteArray fileData = file.readAll();
    file.close();
    
    // Get file size for encoding
    qint64 fileSize = fileData.size();
    
    // Base64 encode filename and file size
    QString filenameStr = QString::fromStdString(filename);
    QByteArray filenameBytes = filenameStr.toUtf8();
    QByteArray fileSizeBytes = QString::number(fileSize).toUtf8();
    
    QString filenameEncoded = filenameBytes.toBase64();
    QString fileSizeEncoded = fileSizeBytes.toBase64();
    
    // Debug logging
    std::cout << "🔧 FILETRANSFER: Building multipart form data:" << std::endl;
    std::cout << "   Original filename: " << filename << std::endl;
    std::cout << "   File size: " << fileSize << " bytes" << std::endl;
    std::cout << "   filename_encrypted: " << filenameEncoded.toStdString() << std::endl;
    std::cout << "   file_size_encrypted: " << fileSizeEncoded.toStdString() << std::endl;
    std::cout << "   file_data_hmac: temp-hmac" << std::endl;
    
    std::stringstream formData;
    
    // Add file field (the main file data)
    formData << "--" << boundary_ << "\r\n";
    formData << "Content-Disposition: form-data; name=\"file\"; filename=\"" << filename << "\"\r\n";
    formData << "Content-Type: application/octet-stream\r\n\r\n";
    
    // Write file data
    formData.write(fileData.constData(), fileData.size());
    formData << "\r\n";
    
    // Add filename_encrypted field (base64 encoded filename)
    formData << "--" << boundary_ << "\r\n";
    formData << "Content-Disposition: form-data; name=\"filename_encrypted\"\r\n\r\n";
    formData << filenameEncoded.toStdString() << "\r\n";
    
    // Add file_size_encrypted field (base64 encoded file size)
    formData << "--" << boundary_ << "\r\n";
    formData << "Content-Disposition: form-data; name=\"file_size_encrypted\"\r\n\r\n";
    formData << fileSizeEncoded.toStdString() << "\r\n";
    
    // Add file_data_hmac field (temporary string for now)
    formData << "--" << boundary_ << "\r\n";
    formData << "Content-Disposition: form-data; name=\"file_data_hmac\"\r\n\r\n";
    formData << "temp-hmac" << "\r\n";
    
    // End boundary
    formData << "--" << boundary_ << "--\r\n";
    
    std::string result = formData.str();
    
    return result;
} 