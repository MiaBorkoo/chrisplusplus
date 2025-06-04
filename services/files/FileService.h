#pragma once

#include "../ApiService.h"
#include "../../network/Client.h"
#include <QObject>
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include <memory>

struct FileInfo {
    QString name;
    qint64 size;
    QString uploadDate;
    QStringList acl;
    virtual ~FileInfo() = default;  // Make the class polymorphic
};

struct SharedFileInfo : public FileInfo {
    QString sharedBy;  // Username of who shared the file
};

class FileService : public ApiService {
    Q_OBJECT
public:
    explicit FileService(std::shared_ptr<Client> client = nullptr, QObject* parent = nullptr);
    ~FileService() override = default;

    // File operations
    void uploadFile(const QString& filePath);
    void deleteFile(const QString& fileName);
    void listFiles(int page = 1, int pageSize = 50);
    void downloadFile(const QString& fileName, const QString& savePath);
    
    // Shared file operations
    void listSharedFiles(int page = 1, int pageSize = 50);

    // Access control operations
    void grantAccess(const QString& fileName, const QString& username);
    void revokeAccess(const QString& fileName, const QString& username);
    void getUsersWithAccess(const QString& fileName);

    // Implementation of ApiService
    bool isInitialized() const override {
        return m_client != nullptr;
    }

signals:
    // File operation signals
    void uploadProgress(qint64 bytesSent, qint64 bytesTotal);
    void uploadComplete(bool success, const QString& fileName);
    void downloadProgress(qint64 bytesReceived, qint64 bytesTotal);
    void downloadComplete(bool success, const QString& fileName);
    void deleteComplete(bool success, const QString& fileName);
    
    // List operation signals with pagination info
    void fileListReceived(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages);
    void sharedFileListReceived(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages);

    // Access control signals
    void accessGranted(bool success, const QString& fileName, const QString& username);
    void accessRevoked(bool success, const QString& fileName, const QString& username);
    void usersWithAccessReceived(const QString& fileName, const QStringList& users);

private slots:
    void handleResponseReceived(int status, const QJsonObject& data);
    void handleNetworkError(const QString& error);

private:
    std::shared_ptr<Client> m_client;

    // Helper methods
    void handleFileListResponse(const QJsonObject& data, bool isSharedList = false);
    void handleAccessResponse(const QJsonObject& data);
    void handleUploadResponse(const QJsonObject& data);
    void handleDownloadResponse(const QJsonObject& data);
    void handleDeleteResponse(const QJsonObject& data);
};
