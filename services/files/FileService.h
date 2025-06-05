#pragma once

#include "../ApiService.h"
// SECURE CONNECTIONS: Replace basic client with secure components
#include "../../network/Client.h"
#include "../../fileIO/fileTransfer.h"
#include "../../sockets/SSLContext.h"
#include <QObject>
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include <QJsonArray>
#include <memory>

// Keep exactly the same structs
struct FileInfo {
    QString name;
    qint64 size;
    QString uploadDate;
    QStringList acl;
    
    FileInfo() : size(0) {}
    virtual ~FileInfo() = default;  // Make polymorphic for dynamic_cast
};

struct SharedFileInfo : public FileInfo {
    QString sharedBy;
};

class FileService : public ApiService {
    Q_OBJECT
public:
    // CHANGE: Use shared Client instead of creating separate HttpClient
    explicit FileService(std::shared_ptr<Client> client, QObject* parent = nullptr);
    ~FileService() override = default;

    // Initialize FileTransfer when SSLContext becomes available
    void initializeFileTransfer(std::shared_ptr<SSLContext> sslContext);

    // Keep ALL existing methods exactly as they are
    void uploadFile(const QString& filePath);
    void deleteFile(const QString& fileName);
    void listFiles(int page = 1, int pageSize = 50);
    void downloadFile(const QString& fileName, const QString& savePath);
    void listSharedFiles(int page = 1, int pageSize = 50);
    void grantAccess(const QString& fileName, const QString& username);
    void revokeAccess(const QString& fileName, const QString& username);
    void getUsersWithAccess(const QString& fileName);
    void getFileMetadata(const QString& fileId);
    void getFileAuditLogs(const QString& fileId, int limit = 50, int offset = 0);

    // Set auth token for authenticated requests
    void setAuthToken(const QString& token);

    // Keep same isInitialized logic
    bool isInitialized() const override {
        return m_client != nullptr;
    }

signals:
    // Keep ALL existing signals exactly as they are
    void uploadComplete(bool success, const QString& fileName);
    void downloadComplete(bool success, const QString& fileName);
    void deleteComplete(bool success, const QString& fileName);
    void fileListReceived(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages);
    void sharedFileListReceived(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages);
    void accessGranted(bool success, const QString& fileName, const QString& username);
    void accessRevoked(bool success, const QString& fileName, const QString& username);
    void usersWithAccessReceived(const QString& fileName, const QStringList& users);
    void fileMetadataReceived(const QString& fileId, const QJsonObject& metadata);
    void auditLogsReceived(const QString& fileId, const QJsonArray& logs);

    // Add new progress signals
    void uploadProgress(const QString& fileName, qint64 bytesTransferred, qint64 totalBytes);
    void downloadProgress(const QString& fileName, qint64 bytesTransferred, qint64 totalBytes);

private slots:
    // Keep ALL existing slots exactly as they are
    void handleResponseReceived(int status, const QJsonObject& data);
    void handleNetworkError(const QString& error);
    
    // File transfer completion handlers
    void handleUploadCompleted(bool success, const TransferResult& result);
    void handleDownloadCompleted(bool success, const TransferResult& result);
    void handleTransferProgress(qint64 bytesTransferred, qint64 totalBytes);

private:
    // SECURE NETWORKING: Use shared Client like AuthService
    std::shared_ptr<Client> m_client;
    std::shared_ptr<FileTransfer> m_fileTransfer;
    QString m_authToken;

    // Current operation tracking for progress signals
    QString m_currentFileName;

    // Keep ALL existing helper methods exactly as they are
    void handleFileListResponse(const QJsonObject& data, bool isSharedList = false);
    void handleAccessResponse(const QJsonObject& data);
    void handleUploadResponse(const QJsonObject& data);
    void handleDownloadResponse(const QJsonObject& data);
    void handleDeleteResponse(const QJsonObject& data);
    void handleMetadataResponse(const QJsonObject& data);
    void handleAuditLogsResponse(const QJsonObject& data);
    
    // Helper to convert Qt requests to secure HTTP requests (for consistency)
    HttpRequest createSecureRequest(const QString& endpoint, const QString& method, const QJsonObject& payload = QJsonObject());
    void sendSecureRequest(const QString& endpoint, const QString& method, const QJsonObject& payload = QJsonObject());
};