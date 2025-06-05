#pragma once

#include <QString>
#include <QObject>
#include <memory>
#include <vector>

// Forward declarations to avoid header dependencies
class FileEncryptionEngine;
class FileOperationsClient;
class SharingServiceClient;
class AuditServiceClient;
class SSLContext;

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

/**
 * SecureFileHandler - Clean abstraction for the secure file system
 * Implements the CS4455-compliant encryption architecture:
 * - Argon2id key derivation for MEK wrapper keys
 * - AES-256-GCM encryption for files and MEK
 * - Fresh DEK per file
 * - Proper HMAC authentication
 */
class SecureFileHandler {
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

    // MEK management according to diagram
    bool deriveUserMEK(const QString& password, const QString& salt);
    bool updatePasswordAndReencryptMEK(const QString& oldPassword, const QString& newPassword, const QString& salt);
    bool isInitialized() const;

    // Secure file operations
    SecureUploadResult uploadFileSecurely(const QString& filePath, const QString& authToken);
    SecureDownloadResult downloadFileSecurely(const QString& fileName, const QString& savePath, const QString& authToken);
    bool deleteFileSecurely(const QString& fileName, const QString& authToken);

    // File sharing operations
    bool shareFileSecurely(const QString& fileName, const QString& recipientUsername, const QString& authToken);
    bool revokeFileAccess(const QString& fileName, const QString& username, const QString& authToken);

    // Metadata and audit operations
    bool getFileMetadata(const QString& fileId, const QString& authToken);
    bool getFileAuditLogs(const QString& fileId, const QString& authToken);

    // Metadata decryption for UI display
    std::string decryptMetadata(const std::string& encryptedData) const;

private:
    // Core encryption components
    std::unique_ptr<FileEncryptionEngine> m_encryptionEngine;
    std::shared_ptr<FileOperationsClient> m_fileOperationsClient;
    std::shared_ptr<SharingServiceClient> m_sharingServiceClient;
    std::shared_ptr<AuditServiceClient> m_auditServiceClient;
    
    // User encryption context
    std::vector<uint8_t> m_userMEK;         // Master Encryption Key (256-bit)
    std::vector<uint8_t> m_mekWrapperKey;   // Derived from password + salt via Argon2id
    std::vector<uint8_t> m_encryptedMEK;    // MEK encrypted with wrapper key
    
    // Server connection details
    QString m_serverHost;
    QString m_serverPort;
    
    // Initialization state
    bool m_isInitialized;
    
    // Helper methods for encryption flow
    bool deriveMEKWrapperKey(const QString& password, const QString& salt);
    bool generateOrRecoverMEK();
    bool encryptMEKForStorage();
    bool decryptMEKFromStorage();
    
    // Security validation
    bool validateEncryptionComponents() const;
}; 