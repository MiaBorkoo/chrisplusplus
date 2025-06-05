#include "FileService.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QFileInfo>
#include <QUrl>

FileService::FileService(std::shared_ptr<Client> client, QObject* parent)
    : ApiService(parent), m_client(client)
{
    if (m_client) {
        connect(m_client.get(), SIGNAL(responseReceived(int, QJsonObject)),
                this, SLOT(handleResponseReceived(int, QJsonObject)));
        connect(m_client.get(), SIGNAL(networkError(QString)),
                this, SLOT(handleNetworkError(QString)));
    }
}

void FileService::uploadFile(const QString& filePath) {
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) {
        reportError("File does not exist: " + filePath);
        return;
    }

    QJsonObject payload;
    payload["filename"] = fileInfo.fileName();
    payload["size"] = QString::number(fileInfo.size());

    m_client->sendRequest("/api/files/upload", "POST", payload);
}

void FileService::downloadFile(const QString& fileName, const QString& savePath) {
    QJsonObject payload;
    payload["filename"] = fileName;
    payload["save_path"] = savePath;

    m_client->sendRequest("/api/files/download", "GET", payload);
}

void FileService::deleteFile(const QString& fileName) {
    QJsonObject payload;
    payload["filename"] = fileName;

    m_client->sendRequest("/api/files/delete", "DELETE", payload);
}

void FileService::listFiles(int page, int pageSize) {
    QJsonObject payload;
    payload["limit"] = pageSize;
    payload["offset"] = page * pageSize;

    m_client->sendRequest("/api/files/", "GET", payload);
}

void FileService::listSharedFiles(int page, int pageSize) {
    QJsonObject payload;
    payload["limit"] = pageSize;
    payload["offset"] = page * pageSize;

    m_client->sendRequest("/api/files/shares/received", "GET", payload);
}

void FileService::grantAccess(const QString& fileName, const QString& username) {
    QJsonObject payload;
    payload["recipient_username"] = username;

    m_client->sendRequest("/api/files/share", "POST", payload);
}

void FileService::revokeAccess(const QString& fileName, const QString& username) {
    QString shareId = "placeholder_share_id";
    QJsonObject payload;

    m_client->sendRequest("/api/files/share/" + shareId, "DELETE", payload);
}

void FileService::getUsersWithAccess(const QString& fileName) {
    QString fileId = "placeholder_file_id";
    m_client->sendRequest("/api/files/" + fileId + "/shares", "GET", QJsonObject());
}

void FileService::getFileMetadata(const QString& fileId) {
    QJsonObject payload;
    
    QString endpoint = QString("/api/files/%1/metadata").arg(fileId);
    m_client->sendRequest(endpoint, "GET", payload);
}

void FileService::getFileAuditLogs(const QString& fileId, int limit, int offset) {
    QJsonObject payload;
    payload["limit"] = limit;
    payload["offset"] = offset;
    
    QString endpoint = QString("/api/files/%1/audit").arg(fileId);
    m_client->sendRequest(endpoint, "GET", payload);
}

void FileService::handleResponseReceived(int status, const QJsonObject& data) {
    QString endpoint = data.value("endpoint").toString();

    if (endpoint == "/api/files/" || endpoint.startsWith("/api/files/?")) {
        handleFileListResponse(data, false);
    }
    else if (endpoint == "/api/files/shares/received" || endpoint.startsWith("/api/files/shares/received?")) {
        handleFileListResponse(data, true);
    }
    else if (endpoint.contains("/shares") && !endpoint.contains("received")) {
        handleAccessResponse(data);
    }
    else if (endpoint == "/api/files/upload") {
        handleUploadResponse(data);
    }
    else if (endpoint.contains("/download")) {
        handleDownloadResponse(data);
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

void FileService::handleNetworkError(const QString& error) {
    reportError(error);
}

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
