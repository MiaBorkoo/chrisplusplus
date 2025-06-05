#include "FileService.h"
#include "SecureFileHandler.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QFileInfo>
#include <QUrl>
#include <QDateTime>
#include <iostream>
#include <QDebug>
#include "../utils/Config.h"  // Add Config include for server details
#include <QCryptographicHash>

// Add encryption system includes AFTER FileService.h to avoid conflicts
#include "files/encryption/FileEncryptionEngine.h"
#include "files/client/FileOperationsClient.h"
#include "files/models/DataModels.h"

FileService::FileService(std::shared_ptr<Client> client, QObject* parent)
    : ApiService(parent), m_client(client)
{
    // Connect to the same Client that AuthService uses
    if (m_client) {
        connect(m_client.get(), SIGNAL(responseReceived(int, QJsonObject)), 
                this, SLOT(handleResponseReceived(int, QJsonObject)));
        connect(m_client.get(), SIGNAL(networkError(QString)),
                this, SLOT(handleNetworkError(QString)));
    }
    
    // Initialize secure file handler
    m_secureHandler = std::make_unique<SecureFileHandler>();
    
    // FileTransfer will be initialized later when SSLContext is available
    m_fileTransfer = nullptr;
    
    std::cout << "🔐 FILESERVICE: Initialized with secure file handler" << std::endl;
}

// Custom destructor needed for forward declarations with unique_ptr
FileService::~FileService() = default;

void FileService::initializeSecureSystem(std::shared_ptr<SSLContext> sslContext, const QString& userPassword, const QString& userSalt)
{
    std::cout << "🔐 FILESERVICE: Initializing secure system with user credentials" << std::endl;
    
    if (!m_secureHandler) {
        std::cout << "❌ FILESERVICE: Secure handler not available" << std::endl;
        return;
    }
    
    // Get server details from config
    Config& config = Config::getInstance();
    QString serverHost = config.getServerHost();
    QString serverPort = config.getServerPort();  // Already a QString
    
    // Initialize the secure system with user credentials
    bool success = m_secureHandler->initializeWithCredentials(
        sslContext,
        serverHost,
        serverPort,
        userPassword,
        userSalt
    );
    
    if (success) {
        std::cout << "✅ FILESERVICE: Secure system initialized successfully" << std::endl;
    } else {
        std::cout << "❌ FILESERVICE: Secure system initialization failed" << std::endl;
    }
}

void FileService::setAuthToken(const QString& token) {
    std::cout << "🔑 FILESERVICE: setAuthToken called with token: " << token.left(20).toStdString() << "..." << std::endl;
    m_authToken = token;
    
    // Set token on the shared client for Authorization headers
    if (m_client) {
        std::cout << "🔑 FILESERVICE: Setting auth token on shared Client" << std::endl;
        m_client->setAuthToken(token);
    } else {
        std::cout << "❌ FILESERVICE: Client not available for auth token setting" << std::endl;
    }
    
    // Also set on FileTransfer if it exists
    if (m_fileTransfer) {
        std::cout << "🔑 FILESERVICE: Setting auth token on FileTransfer" << std::endl;
        m_fileTransfer->setAuthToken(token);
        qDebug() << "Set auth token on FileTransfer for secure file operations";
    } else {
        std::cout << "⚠️ FILESERVICE: FileTransfer not initialized yet, token will be set later" << std::endl;
    }
}

void FileService::uploadFile(const QString& filePath) {
    std::cout << "🔥 FILESERVICE: uploadFile called with path: " << filePath.toStdString() << std::endl;
    
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) {
        std::cout << "❌ FILESERVICE: File does not exist: " << filePath.toStdString() << std::endl;
        reportError("File does not exist: " + filePath);
        return;
    }

    // Store current filename for progress tracking
    m_currentFileName = fileInfo.fileName();
    std::cout << "📁 FILESERVICE: Starting SECURE upload for file: " << m_currentFileName.toStdString() << std::endl;
    
    // SECURE PATH: Use SecureFileHandler if available and initialized
    if (m_secureHandler && m_secureHandler->isInitialized()) {
        std::cout << "🔐 FILESERVICE: Using SECURE upload path" << std::endl;
        
        auto result = m_secureHandler->uploadFileSecurely(filePath, m_authToken);
        
        if (result.success) {
            std::cout << "✅ FILESERVICE: Secure upload completed successfully!" << std::endl;
            std::cout << "   File ID: " << result.fileId.toStdString() << std::endl;
            emit uploadComplete(true, m_currentFileName);
        } else {
            std::cout << "❌ FILESERVICE: Secure upload failed: " << result.error.toStdString() << std::endl;
            reportError("Secure upload failed: " + result.error);
            emit uploadComplete(false, m_currentFileName);
        }
        return;
    }
    
    // FALLBACK PATH: Use legacy FileTransfer (insecure)
    std::cout << "⚠️ FILESERVICE: Secure system not available, using LEGACY upload" << std::endl;
    
    if (!m_fileTransfer) {
        reportError("FileTransfer not initialized.");
        emit uploadComplete(false, m_currentFileName);
        return;
    }

    // Legacy upload using FileTransfer
    m_fileTransfer->uploadFileAsync(filePath, "/api/files/upload");
}

void FileService::downloadFile(const QString& fileName, const QString& savePath) {
    std::cout << "⬇️ FILESERVICE: downloadFile called for: " << fileName.toStdString() << std::endl;
    
    // Store current filename for progress tracking
    m_currentFileName = fileName;
    
    // SECURE PATH: Use SecureFileHandler if available
    if (m_secureHandler && m_secureHandler->isInitialized()) {
        std::cout << "🔐 FILESERVICE: Using SECURE download path" << std::endl;
        
        auto result = m_secureHandler->downloadFileSecurely(fileName, savePath, m_authToken);
        
        if (result.success) {
            std::cout << "✅ FILESERVICE: Secure download completed successfully!" << std::endl;
            emit downloadComplete(true, m_currentFileName);
        } else {
            std::cout << "❌ FILESERVICE: Secure download failed: " << result.error.toStdString() << std::endl;
            reportError("Secure download failed: " + result.error);
            emit downloadComplete(false, m_currentFileName);
        }
        return;
    }
    
    // FALLBACK PATH: Use legacy FileTransfer
    std::cout << "⚠️ FILESERVICE: Secure system not available, using LEGACY download" << std::endl;
    
    if (!m_fileTransfer) {
        reportError("FileTransfer not initialized.");
        return;
    }

    // Create download endpoint with filename
    std::string endpoint = "/api/files/download/" + fileName.toStdString();
    
    // Use async file transfer with SSL
    m_fileTransfer->downloadFileAsync(endpoint, savePath);
}

void FileService::deleteFile(const QString& fileName) {
    std::cout << "🗑️ FILESERVICE: deleteFile called for: " << fileName.toStdString() << std::endl;
    
    // SECURE PATH: Use SecureFileHandler if available
    if (m_secureHandler && m_secureHandler->isInitialized()) {
        std::cout << "🔐 FILESERVICE: Using SECURE delete path" << std::endl;
        
        bool success = m_secureHandler->deleteFileSecurely(fileName, m_authToken);
        
        if (success) {
            std::cout << "✅ FILESERVICE: Secure delete completed successfully!" << std::endl;
            emit deleteComplete(true, fileName);
        } else {
            std::cout << "❌ FILESERVICE: Secure delete failed" << std::endl;
            reportError("Secure delete failed");
            emit deleteComplete(false, fileName);
        }
        return;
    }
    
    // FALLBACK PATH: Use legacy Client
    std::cout << "⚠️ FILESERVICE: Secure system not available, using LEGACY delete" << std::endl;
    
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }

    QJsonObject payload;
    payload["filename"] = fileName;

    m_client->sendRequest("/api/files/delete", "DELETE", payload);
}

void FileService::listFiles(int page, int pageSize) {
    std::cout << "FileService::listFiles called with page=" << page << ", pageSize=" << pageSize << std::endl;
    
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }
    
    QJsonObject payload;
    payload["limit"] = pageSize;
    payload["offset"] = page * pageSize;

    std::cout << "About to call m_client->sendRequest for /api/files/" << std::endl;
    m_client->sendRequest("/api/files/", "GET", payload);
    std::cout << "m_client->sendRequest completed" << std::endl;
}

void FileService::listSharedFiles(int page, int pageSize) {
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }

    QJsonObject payload;
    payload["limit"] = pageSize;
    payload["offset"] = page * pageSize;

    m_client->sendRequest("/api/files/shares/received", "GET", payload);
}

void FileService::grantAccess(const QString& fileName, const QString& username) {
    std::cout << "🤝 FILESERVICE: grantAccess called for file: " << fileName.toStdString() << std::endl;
    
    // SECURE PATH: Use SecureFileHandler if available
    if (m_secureHandler && m_secureHandler->isInitialized()) {
        std::cout << "🔐 FILESERVICE: Using SECURE grant access path" << std::endl;
        
        bool success = m_secureHandler->shareFileSecurely(fileName, username, m_authToken);
        
        if (success) {
            std::cout << "✅ FILESERVICE: Secure file sharing completed successfully!" << std::endl;
            emit accessGranted(true, fileName, username);
        } else {
            std::cout << "❌ FILESERVICE: Secure file sharing failed" << std::endl;
            reportError("Secure file sharing failed");
            emit accessGranted(false, fileName, username);
        }
        return;
    }
    
    // FALLBACK PATH: Use legacy Client
    std::cout << "⚠️ FILESERVICE: Secure system not available, using LEGACY grant access" << std::endl;
    
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }

    QJsonObject payload;
    payload["recipient_username"] = username;

    m_client->sendRequest("/api/files/share", "POST", payload);
}

void FileService::revokeAccess(const QString& fileName, const QString& username) {
    std::cout << "🚫 FILESERVICE: revokeAccess called for file: " << fileName.toStdString() << std::endl;
    
    // SECURE PATH: Use SecureFileHandler if available
    if (m_secureHandler && m_secureHandler->isInitialized()) {
        std::cout << "🔐 FILESERVICE: Using SECURE revoke access path" << std::endl;
        
        bool success = m_secureHandler->revokeFileAccess(fileName, username, m_authToken);
        
        if (success) {
            std::cout << "✅ FILESERVICE: Secure access revocation completed successfully!" << std::endl;
            emit accessRevoked(true, fileName, username);
        } else {
            std::cout << "❌ FILESERVICE: Secure access revocation failed" << std::endl;
            reportError("Secure access revocation failed");
            emit accessRevoked(false, fileName, username);
        }
        return;
    }
    
    // FALLBACK PATH: Use legacy Client
    std::cout << "⚠️ FILESERVICE: Secure system not available, using LEGACY revoke access" << std::endl;
    
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }

    QString shareId = "placeholder_share_id";
    QJsonObject payload;

    m_client->sendRequest("/api/files/share/" + shareId, "DELETE", payload);
}

void FileService::getUsersWithAccess(const QString& fileName) {
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }

    QString fileId = "placeholder_file_id";
    m_client->sendRequest("/api/files/" + fileId + "/shares", "GET", QJsonObject());
}

void FileService::getFileMetadata(const QString& fileId) {
    std::cout << "📊 FILESERVICE: getFileMetadata called for: " << fileId.toStdString() << std::endl;
    
    // SECURE PATH: Use SecureFileHandler if available
    if (m_secureHandler && m_secureHandler->isInitialized()) {
        std::cout << "🔐 FILESERVICE: Using SECURE metadata path" << std::endl;
        
        bool success = m_secureHandler->getFileMetadata(fileId, m_authToken);
        
        if (!success) {
            std::cout << "❌ FILESERVICE: Secure metadata retrieval failed" << std::endl;
            reportError("Secure metadata retrieval failed");
        }
        return;
    }
    
    // FALLBACK PATH: Use legacy Client
    std::cout << "⚠️ FILESERVICE: Secure system not available, using LEGACY metadata" << std::endl;
    
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }

    QJsonObject payload;
    
    QString endpoint = QString("/api/files/%1/metadata").arg(fileId);
    m_client->sendRequest(endpoint, "GET", payload);
}

void FileService::getFileAuditLogs(const QString& fileId, int limit, int offset) {
    std::cout << "📝 FILESERVICE: getFileAuditLogs called for: " << fileId.toStdString() << std::endl;
    
    // SECURE PATH: Use SecureFileHandler if available
    if (m_secureHandler && m_secureHandler->isInitialized()) {
        std::cout << "🔐 FILESERVICE: Using SECURE audit logs path" << std::endl;
        
        bool success = m_secureHandler->getFileAuditLogs(fileId, m_authToken);
        
        if (!success) {
            std::cout << "❌ FILESERVICE: Secure audit logs retrieval failed" << std::endl;
            reportError("Secure audit logs retrieval failed");
        }
        return;
    }
    
    // FALLBACK PATH: Use legacy Client
    std::cout << "⚠️ FILESERVICE: Secure system not available, using LEGACY audit logs" << std::endl;
    
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }

    QJsonObject payload;
    payload["limit"] = limit;
    payload["offset"] = offset;
    
    QString endpoint = QString("/api/files/%1/audit").arg(fileId);
    m_client->sendRequest(endpoint, "GET", payload);
}

void FileService::deriveUserMEK(const QString& password, const QString& salt)
{
    std::cout << "🔑 FILESERVICE: deriveUserMEK called" << std::endl;
    
    if (m_secureHandler) {
        bool success = m_secureHandler->deriveUserMEK(password, salt);
        if (success) {
            std::cout << "✅ FILESERVICE: User MEK derived successfully" << std::endl;
        } else {
            std::cout << "❌ FILESERVICE: User MEK derivation failed" << std::endl;
        }
    } else {
        std::cout << "❌ FILESERVICE: Secure handler not available for MEK derivation" << std::endl;
    }
}

void FileService::updatePasswordAndReencryptMEK(const QString& oldPassword, const QString& newPassword, const QString& salt)
{
    std::cout << "🔄 FILESERVICE: updatePasswordAndReencryptMEK called" << std::endl;
    
    if (m_secureHandler) {
        bool success = m_secureHandler->updatePasswordAndReencryptMEK(oldPassword, newPassword, salt);
        if (success) {
            std::cout << "✅ FILESERVICE: Password updated and MEK re-encrypted successfully" << std::endl;
        } else {
            std::cout << "❌ FILESERVICE: Password update and MEK re-encryption failed" << std::endl;
        }
    } else {
        std::cout << "❌ FILESERVICE: Secure handler not available for password update" << std::endl;
    }
}

bool FileService::isSecureSystemReady() const
{
    return m_secureHandler && m_secureHandler->isInitialized();
}

// File transfer completion handlers
void FileService::handleUploadCompleted(bool success, const TransferResult& result) {
    emit uploadComplete(success, m_currentFileName);
}

void FileService::handleDownloadCompleted(bool success, const TransferResult& result) {
    emit downloadComplete(success, m_currentFileName);
}

void FileService::handleTransferProgress(qint64 bytesTransferred, qint64 totalBytes) {
    if (!m_currentFileName.isEmpty()) {
        emit uploadProgress(m_currentFileName, bytesTransferred, totalBytes);
        emit downloadProgress(m_currentFileName, bytesTransferred, totalBytes);
    }
}

void FileService::handleNetworkError(const QString& error) {
    reportError(error);
}

void FileService::handleResponseReceived(int status, const QJsonObject& data) {
    std::cout << "FileService::handleResponseReceived - Status: " << status << std::endl;
    
    QString endpoint = data.value("endpoint").toString();
    std::cout << "Endpoint: " << endpoint.toStdString() << std::endl;
    
    if (endpoint == "/api/files/" || endpoint.startsWith("/api/files/?")) {
        handleFileListResponse(data, false);
    }
    else if (endpoint == "/api/files/shares/received" || endpoint.startsWith("/api/files/shares/received?")) {
        handleFileListResponse(data, true);
    }
    else if (endpoint == "/api/files/upload") {
        handleUploadResponse(data);
    }
    else if (endpoint.contains("/shares") && !endpoint.contains("received")) {
        handleAccessResponse(data);
    }
    else if (endpoint == "/api/files/delete") {
        handleDeleteResponse(data);
    }
    else if (endpoint.contains("/metadata")) {
        handleMetadataResponse(data);
    }
    else if (endpoint.contains("/audit")) {
        handleAuditLogsResponse(data);
    }
    else if (endpoint == "/api/files/share" || endpoint.contains("/api/files/share/")) {
        handleAccessResponse(data);
    }
    else {
        std::cout << "Unhandled endpoint response: \"" << endpoint.toStdString() << "\" Status: " << status << std::endl;
    }
}

// Keep all existing response handlers for MVC compatibility
void FileService::handleFileListResponse(const QJsonObject& data, bool isSharedList) {
    QList<MvcFileInfo> files;
    
    // FIXED: Parse correct field names from server response
    QJsonArray fileArray;
    if (isSharedList) {
        fileArray = data.value("shared_files").toArray();
    } else {
        fileArray = data.value("owned_files").toArray();
    }
    
    int totalFiles = data.value("total_files").toInt();
    int currentPage = data.value("current_page").toInt();
    int totalPages = data.value("total_pages").toInt();

    for (const QJsonValue& value : fileArray) {
        QJsonObject obj = value.toObject();
        
        if (isSharedList) {
            MvcSharedFileInfo info;
            info.name = obj["filename_encrypted"].toString();
            info.size = obj["file_size_encrypted"].toString().toLongLong();
            
            // Convert timestamp to readable date
            qint64 timestamp = obj["upload_timestamp"].toVariant().toLongLong();
            QDateTime dateTime = QDateTime::fromSecsSinceEpoch(timestamp);
            info.uploadDate = dateTime.toString("yyyy-MM-dd hh:mm:ss");
            
            info.sharedBy = obj["shared_by"].toString();
            
            if (obj.contains("acl")) {
                QJsonArray aclArray = obj["acl"].toArray();
                for (const QJsonValue& aclValue : aclArray) {
                    info.acl.append(aclValue.toString());
                }
            }
            files.append(info);
        } else {
            MvcFileInfo info;
            info.name = obj["filename_encrypted"].toString();
            info.size = obj["file_size_encrypted"].toString().toLongLong();
            
            // Convert timestamp to readable date  
            qint64 timestamp = obj["upload_timestamp"].toVariant().toLongLong();
            QDateTime dateTime = QDateTime::fromSecsSinceEpoch(timestamp);
            info.uploadDate = dateTime.toString("yyyy-MM-dd hh:mm:ss");
            
            if (obj.contains("acl")) {
                QJsonArray aclArray = obj["acl"].toArray();
                for (const QJsonValue& aclValue : aclArray) {
                    info.acl.append(aclValue.toString());
                }
            }
            files.append(info);
        }
    }

    if (isSharedList) {
        emit sharedFileListReceived(files, totalFiles, currentPage, totalPages);
    } else {
        emit fileListReceived(files, totalFiles, currentPage, totalPages);
    }
}

void FileService::handleAccessResponse(const QJsonObject& data) {
    QString fileName = data.value("filename").toString();
    bool success = data.value("success").toBool();
    QString endpoint = data.value("endpoint").toString();

    if (endpoint.endsWith("/access")) {
        QStringList users;
        QJsonArray usersArray = data["users"].toArray();
        for (const QJsonValue& value : usersArray) {
            users.append(value.toString());
        }
        emit usersWithAccessReceived(fileName, users);
    }
    else if (endpoint.contains("/grant")) {
        QString username = data.value("username").toString();
        emit accessGranted(success, fileName, username);
    }
    else if (endpoint.contains("/revoke")) {
        QString username = data.value("username").toString();
        emit accessRevoked(success, fileName, username);
    }
}

void FileService::handleUploadResponse(const QJsonObject& data) {
    bool success = data.value("success").toBool();
    QString fileName = data.value("filename").toString();
    emit uploadComplete(success, fileName);
}

void FileService::handleDownloadResponse(const QJsonObject& data) {
    bool success = data.value("success").toBool();
    QString fileName = data.value("filename").toString();
    emit downloadComplete(success, fileName);
}

void FileService::handleDeleteResponse(const QJsonObject& data) {
    bool success = data.value("success").toBool();
    QString fileName = data.value("filename").toString();
    emit deleteComplete(success, fileName);
}

void FileService::handleMetadataResponse(const QJsonObject& data) {
    QString fileId = data.value("file_id").toString();
    QJsonObject metadata;
    metadata["filename_encrypted"] = data.value("filename_encrypted");
    metadata["file_size_encrypted"] = data.value("file_size_encrypted");
    metadata["upload_timestamp"] = data.value("upload_timestamp");
    metadata["file_data_hmac"] = data.value("file_data_hmac");
    metadata["server_storage_path"] = data.value("server_storage_path");
    
    emit fileMetadataReceived(fileId, metadata);
}

void FileService::handleAuditLogsResponse(const QJsonObject& data) {
    QString fileId = data.value("file_id").toString();
    QJsonArray logs = data.value("logs").toArray();
    
    emit auditLogsReceived(fileId, logs);
}

// Initialize FileTransfer when SSLContext becomes available (kept for fallback)
void FileService::initializeFileTransfer(std::shared_ptr<SSLContext> sslContext) {
    std::cout << "🔧 FILESERVICE: initializeFileTransfer called" << std::endl;
    
    if (sslContext) {
        std::cout << "✅ FILESERVICE: SSLContext available, creating FileTransfer" << std::endl;
        m_fileTransfer = std::make_shared<FileTransfer>(*sslContext);
        
        // Use the SAME HttpClient as the Client for consistent connection
        if (m_client) {
            std::cout << "🔗 FILESERVICE: Setting HttpClient from shared Client" << std::endl;
            m_fileTransfer->setHttpClient(m_client->getHttpClient());
            qDebug() << "FileTransfer now uses shared HttpClient from Client";
        } else {
            std::cout << "❌ FILESERVICE: Client not available for HttpClient sharing" << std::endl;
        }
        
        // Set auth token if we already have one
        if (!m_authToken.isEmpty()) {
            std::cout << "🔑 FILESERVICE: Setting existing auth token on FileTransfer" << std::endl;
            m_fileTransfer->setAuthToken(m_authToken);
            qDebug() << "Set existing auth token on newly created FileTransfer";
        } else {
            std::cout << "⚠️ FILESERVICE: No auth token available during FileTransfer init" << std::endl;
        }
        
        // Connect FileTransfer signals
        std::cout << "🔌 FILESERVICE: Connecting FileTransfer signals" << std::endl;
        connect(m_fileTransfer.get(), &FileTransfer::uploadCompleted,
                this, &FileService::handleUploadCompleted);
        connect(m_fileTransfer.get(), &FileTransfer::downloadCompleted,
                this, &FileService::handleDownloadCompleted);
        connect(m_fileTransfer.get(), &FileTransfer::progressUpdated,
                this, &FileService::handleTransferProgress);
        connect(m_fileTransfer.get(), &FileTransfer::transferFailed,
                this, &FileService::handleNetworkError);
        std::cout << "✅ FILESERVICE: FileTransfer initialization complete" << std::endl;
    } else {
        std::cout << "❌ FILESERVICE: SSLContext is null, cannot initialize FileTransfer" << std::endl;
    }
}
