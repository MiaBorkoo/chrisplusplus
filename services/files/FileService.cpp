#include "FileService.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QFileInfo>
#include <QUrl>
#include <iostream>
#include <QDebug>
#include "../utils/Config.h"  // Add Config include for server details

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
    
    // FileTransfer will be initialized later when SSLContext is available
    m_fileTransfer = nullptr;
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

    if (!m_fileTransfer) {
        std::cout << "❌ FILESERVICE: FileTransfer not initialized!" << std::endl;
        reportError("FileTransfer not initialized.");
        return;
    }

    // Store current filename for progress tracking
    m_currentFileName = fileInfo.fileName();
    std::cout << "📁 FILESERVICE: Starting upload for file: " << m_currentFileName.toStdString() << std::endl;
    
    // Use async file transfer with SSL
    std::cout << "📡 FILESERVICE: Calling m_fileTransfer->uploadFileAsync..." << std::endl;
    m_fileTransfer->uploadFileAsync(filePath, "/api/files/upload");
    std::cout << "✅ FILESERVICE: uploadFileAsync call completed" << std::endl;
}

void FileService::downloadFile(const QString& fileName, const QString& savePath) {
    if (!m_fileTransfer) {
        reportError("FileTransfer not initialized.");
        return;
    }

    // Store current filename for progress tracking
    m_currentFileName = fileName;
    
    // Create download endpoint with filename
    std::string endpoint = "/api/files/download/" + fileName.toStdString();
    
    // Use async file transfer with SSL
    m_fileTransfer->downloadFileAsync(endpoint, savePath);
}

void FileService::deleteFile(const QString& fileName) {
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
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }

    QJsonObject payload;
    payload["recipient_username"] = username;

    m_client->sendRequest("/api/files/share", "POST", payload);
}

void FileService::revokeAccess(const QString& fileName, const QString& username) {
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
    if (!m_client) {
        reportError("Client not initialized");
        return;
    }

    QJsonObject payload;
    
    QString endpoint = QString("/api/files/%1/metadata").arg(fileId);
    m_client->sendRequest(endpoint, "GET", payload);
}

void FileService::getFileAuditLogs(const QString& fileId, int limit, int offset) {
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

// Helper to create secure requests (for consistency with header structure)
HttpRequest FileService::createSecureRequest(const QString& endpoint, const QString& method, const QJsonObject& payload) {
    HttpRequest request;
    request.method = method.toStdString();
    request.path = endpoint.toStdString();
    
    // Add authorization header
    if (!m_authToken.isEmpty()) {
        std::cout << "Adding auth token to request: " << m_authToken.left(20).toStdString() << "..." << std::endl;
        request.headers["Authorization"] = "Bearer " + m_authToken.toStdString();
    } else {
        std::cout << "WARNING: No auth token available!" << std::endl;
    }
    
    // Add JSON content if payload exists
    if (!payload.isEmpty()) {
        request.headers["Content-Type"] = "application/json";
        QJsonDocument doc(payload);
        request.body = doc.toJson(QJsonDocument::Compact).toStdString();
    }
    
    return request;
}

// Send secure requests using the shared client
void FileService::sendSecureRequest(const QString& endpoint, const QString& method, const QJsonObject& payload) {
    std::cout << "sendSecureRequest called - endpoint: " << endpoint.toStdString() << ", method: " << method.toStdString() << std::endl;
    
    if (!m_client) {
        std::cout << "ERROR: Client not initialized!" << std::endl;
        reportError("Client not initialized");
        return;
    }
    
    // Use the shared client instead of separate HTTP client
    m_client->sendRequest(endpoint, method, payload);
    }

// Handle file transfer completion
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
}

// Keep all existing response handlers exactly the same
void FileService::handleFileListResponse(const QJsonObject& data, bool isSharedList) {
    QList<FileInfo> files;
    QJsonArray fileArray = data.value("files").toArray();
    
    int totalFiles = data.value("total_files").toInt();
    int currentPage = data.value("current_page").toInt();
    int totalPages = data.value("total_pages").toInt();

    for (const QJsonValue& value : fileArray) {
        QJsonObject obj = value.toObject();
        
        if (isSharedList) {
            SharedFileInfo info;
            info.name = obj["name"].toString();
            info.size = obj["size"].toVariant().toLongLong();
            info.uploadDate = obj["upload_date"].toString();
            info.sharedBy = obj["shared_by"].toString();  // Get the username of who shared it
            
            if (obj.contains("acl")) {
                QJsonArray aclArray = obj["acl"].toArray();
                for (const QJsonValue& aclValue : aclArray) {
                    info.acl.append(aclValue.toString());
                }
            }
            files.append(info);
        } else {
            FileInfo info;
            info.name = obj["name"].toString();
            info.size = obj["size"].toVariant().toLongLong();
            info.uploadDate = obj["upload_date"].toString();
            
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
        // Get users with access response
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

// Add method to initialize FileTransfer when SSLContext becomes available
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
        std::cout << "✅ FILESERVICE: FileTransfer initialization complete" << std::endl;
    } else {
        std::cout << "❌ FILESERVICE: SSLContext is null, cannot initialize FileTransfer" << std::endl;
    }
}
