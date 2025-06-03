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

    m_client->sendRequest("/files/upload", "POST", payload);
}

void FileService::downloadFile(const QString& fileName, const QString& savePath) {
    QJsonObject payload;
    payload["filename"] = fileName;
    payload["save_path"] = savePath;

    m_client->sendRequest("/files/download", "GET", payload);
}

void FileService::deleteFile(const QString& fileName) {
    QJsonObject payload;
    payload["filename"] = fileName;

    m_client->sendRequest("/files/delete", "DELETE", payload);
}

void FileService::listFiles(int page, int pageSize) {
    QJsonObject payload;
    payload["page"] = page;
    payload["page_size"] = pageSize;

    m_client->sendRequest("/files/list", "GET", payload);
}

void FileService::listSharedFiles(int page, int pageSize) {
    QJsonObject payload;
    payload["page"] = page;
    payload["page_size"] = pageSize;

    m_client->sendRequest("/files/shared", "GET", payload);
}

void FileService::grantAccess(const QString& fileName, const QString& username) {
    QJsonObject payload;
    payload["username"] = username;

    m_client->sendRequest("/files/" + QUrl::toPercentEncoding(fileName) + "/access/grant", "POST", payload);
}

void FileService::revokeAccess(const QString& fileName, const QString& username) {
    QJsonObject payload;
    payload["username"] = username;

    m_client->sendRequest("/files/" + QUrl::toPercentEncoding(fileName) + "/access/revoke", "POST", payload);
}

void FileService::getUsersWithAccess(const QString& fileName) {
    m_client->sendRequest("/files/" + QUrl::toPercentEncoding(fileName) + "/access", "GET", QJsonObject());
}

void FileService::handleResponseReceived(int status, const QJsonObject& data) {
    QString endpoint = data.value("endpoint").toString();

    if (endpoint.startsWith("/files/list")) {
        handleFileListResponse(data, false);
    }
    else if (endpoint.startsWith("/files/shared")) {
        handleFileListResponse(data, true);
    }
    else if (endpoint.contains("/access")) {
        handleAccessResponse(data);
    }
    else if (endpoint == "/files/upload") {
        handleUploadResponse(data);
    }
    else if (endpoint == "/files/download") {
        handleDownloadResponse(data);
    }
    else if (endpoint == "/files/delete") {
        handleDeleteResponse(data);
    }
}

void FileService::handleNetworkError(const QString& error) {
    reportError(error);
}

void FileService::handleFileListResponse(const QJsonObject& data, bool isSharedList) {
    QList<FileInfo> files;
    QJsonArray fileArray = data.value("files").toArray();
    
    // Parse pagination info
    int totalFiles = data.value("total_files").toInt();
    int currentPage = data.value("current_page").toInt();
    int totalPages = data.value("total_pages").toInt();

    for (const QJsonValue& value : fileArray) {
        QJsonObject obj = value.toObject();
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
