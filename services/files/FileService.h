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
#include <QMap>

// MVC-compatible data structures for UI layer
struct MvcFileInfo {
    QString name;           // Decrypted name for display
    QString fileId;         // Server file ID for operations
    QString encryptedName;  // Original encrypted name from server
    qint64 size;
    QString uploadDate;
    QStringList acl;
    
    MvcFileInfo() : size(0) {}
    virtual ~MvcFileInfo() = default;
};

struct MvcSharedFileInfo : public MvcFileInfo {
    QString sharedBy;
};

// Forward declaration for secure implementation
class SecureFileHandler;

class FileService : public ApiService {
    Q_OBJECT
public:
    // CHANGE: Use shared Client instead of creating separate HttpClient
    explicit FileService(std::shared_ptr<Client> client, QObject* parent = nullptr);
    ~FileService() override;  // CHANGED: Custom destructor needed for forward declarations

    // Initialize with SSL context and user credentials
    void initializeSecureSystem(std::shared_ptr<SSLContext> sslContext, const QString& userPassword, const QString& userSalt);
    void initializeFileTransfer(std::shared_ptr<SSLContext> sslContext);

    // File operations - same interface, secure implementation
    void uploadFile(const QString& filePath);
    void deleteFile(const QString& fileId);
    void listFiles(int page = 1, int pageSize = 50);
    void downloadFile(const QString& fileId, const QString& savePath);
    void listSharedFiles(int page = 1, int pageSize = 50);
    void grantAccess(const QString& fileName, const QString& username);
    void revokeAccess(const QString& fileName, const QString& username);
    void getUsersWithAccess(const QString& fileName);
    void getFileMetadata(const QString& fileId);
    void getFileAuditLogs(const QString& fileId, int limit = 50, int offset = 0);

    // Authentication and encryption key management
    void setAuthToken(const QString& token);
    void deriveUserMEK(const QString& password, const QString& salt);
    void updatePasswordAndReencryptMEK(const QString& oldPassword, const QString& newPassword, const QString& salt);

    // Keep same isInitialized logic
    bool isInitialized() const override {
        return m_client != nullptr;
    }

    // Check if secure system is ready
    bool isSecureSystemReady() const;

    //  WORKAROUND: Store original filenames for downloads when server doesn't send Content-Disposition
    void setOriginalFilename(const QString& fileId, const QString& originalName);
    QString getOriginalFilename(const QString& fileId) const;

signals:
    // Keep ALL existing signals exactly as they are but use MVC types
    void uploadComplete(bool success, const QString& fileName);
    void downloadComplete(bool success, const QString& fileName);
    void deleteComplete(bool success, const QString& fileName);
    void fileListReceived(const QList<MvcFileInfo>& files, int totalFiles, int currentPage, int totalPages);
    void sharedFileListReceived(const QList<MvcFileInfo>& files, int totalFiles, int currentPage, int totalPages);
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

    // SECURE SYSTEM: Clean abstraction - no templates or incomplete types in header
    std::unique_ptr<SecureFileHandler> m_secureHandler;
    
    //  WORKAROUND: Map file IDs to original filenames
    QMap<QString, QString> m_originalFilenames;
    
    // Response parsing (shared between secure and legacy)
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