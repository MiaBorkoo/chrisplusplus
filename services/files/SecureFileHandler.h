#pragma once

#include <QString>
#include <QObject>
#include <QFuture>
#include <memory>
#include <vector>
#include <functional>

// Forward declarations to avoid header dependencies
class FileEncryptionEngine;
class FileOperationsClient;
class SharingServiceClient;
class AuditServiceClient;
class SSLContext;
class FileTransfer;
struct TransferResult;
struct FileEncryptionContext;

struct SecureUploadResult {
    bool success;
    QString error;
    QString fileId;
};

struct SecureDownloadResult {
    bool success;
    QString error;
    QString filePath;
};

// Async progress callbacks for encrypted operations
using EncryptionProgressCallback = std::function<void(qint64 bytesProcessed, qint64 totalBytes)>;

/**
 * SecureFileHandler - Clean abstraction for the secure file system
 * 🔥 FIXED: Now wraps existing FileTransfer streaming architecture with encryption
 * instead of doing blocking operations!
 * 
 * Architecture:
 * FileTransfer (async streaming) → Encryption Layer → Secure Network
 */
class SecureFileHandler : public QObject {
    Q_OBJECT

public:
    SecureFileHandler();
    ~SecureFileHandler();

    // Initialization following the encryption diagram
    bool initializeWithCredentials(
        std::shared_ptr<SSLContext> sslContext,
        const QString& serverHost,
        const QString& serverPort,
        const QString& userPassword,
        const QString& encryptionSalt
    );

    // Set the existing FileTransfer for streaming operations
    void setFileTransfer(std::shared_ptr<FileTransfer> fileTransfer);

    // MEK management according to diagram
    bool deriveUserMEK(const QString& password, const QString& salt);
    bool updatePasswordAndReencryptMEK(const QString& oldPassword, const QString& newPassword, const QString& salt);
    bool isInitialized() const;

    // 🔥 ASYNC secure file operations that wrap FileTransfer streaming
    void uploadFileSecurelyAsync(const QString& filePath, const QString& authToken);
    void downloadFileSecurelyAsync(const QString& fileId, const QString& savePath, const QString& authToken);
    bool deleteFileSecurely(const QString& fileId, const QString& authToken);

    // 🔥 LEGACY SYNC methods for backward compatibility (deprecated)
    SecureUploadResult uploadFileSecurely(const QString& filePath, const QString& authToken);
    SecureDownloadResult downloadFileSecurely(const QString& fileId, const QString& savePath, const QString& authToken);

    // File sharing operations
    bool shareFileSecurely(const QString& fileName, const QString& recipientUsername, const QString& authToken);
    bool revokeFileAccess(const QString& fileName, const QString& username, const QString& authToken);

    // Metadata and audit operations
    bool getFileMetadata(const QString& fileId, const QString& authToken);
    bool getFileAuditLogs(const QString& fileId, const QString& authToken);

    // Metadata decryption for UI display
    std::string decryptMetadata(const std::string& encryptedData) const;

signals:
    // Async operation results
    void secureUploadCompleted(bool success, const QString& fileName, const QString& fileId = "");
    void secureDownloadCompleted(bool success, const QString& fileName);
    void secureUploadProgress(const QString& fileName, qint64 bytesProcessed, qint64 totalBytes);
    void secureDownloadProgress(const QString& fileName, qint64 bytesProcessed, qint64 totalBytes);
    void secureOperationFailed(const QString& fileName, const QString& error);

private slots:
    // Handle FileTransfer completion
    void handleUploadCompleted(bool success, const TransferResult& result);
    void handleDownloadCompleted(bool success, const TransferResult& result);
    void handleTransferProgress(qint64 bytesTransferred, qint64 totalBytes);

private:
    // Core encryption components
    std::unique_ptr<FileEncryptionEngine> m_encryptionEngine;
    std::shared_ptr<FileOperationsClient> m_fileOperationsClient;
    std::shared_ptr<SharingServiceClient> m_sharingServiceClient;
    std::shared_ptr<AuditServiceClient> m_auditServiceClient;
    
    // 🔥 INTEGRATION: Use existing FileTransfer for streaming
    std::shared_ptr<FileTransfer> m_fileTransfer;
    
    // User encryption context
    std::vector<uint8_t> m_userMEK;         // Master Encryption Key (256-bit)
    std::vector<uint8_t> m_mekWrapperKey;   // Derived from password + salt via Argon2id
    std::vector<uint8_t> m_encryptedMEK;    // MEK encrypted with wrapper key
    
    // Server connection details
    QString m_serverHost;
    QString m_serverPort;
    
    // Initialization state
    bool m_isInitialized;
    
    // Current operation tracking
    QString m_currentFileName;
    QString m_currentAuthToken;
    QString m_currentTempFilePath; // Track temp file for cleanup
    QString m_currentSavePath;     // Track user's chosen save path for downloads
    
    // Background operation futures
    QFuture<void> m_encryptionFuture;
    QFuture<void> m_decryptionFuture;
    
    // Helper methods for encryption flow
    bool deriveMEKWrapperKey(const QString& password, const QString& salt);
    bool generateOrRecoverMEK();
    bool encryptMEKForStorage();
    bool decryptMEKFromStorage();
    
    // 🔥 STREAMING ENCRYPTION: Process files in chunks
    QString createEncryptedTempFile(const QString& sourceFilePath);
    bool decryptStreamedFile(const QString& encryptedFilePath, const QString& outputPath);
    std::vector<uint8_t> encryptFileData(const std::vector<uint8_t>& fileData, const FileEncryptionContext& context);
    
    // Security validation
    bool validateEncryptionComponents() const;
};