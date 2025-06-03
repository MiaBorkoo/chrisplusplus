#pragma once
#include <QObject>
#include <QString>
#include "../services/files/FileService.h"
#include <memory>

class FileModel : public QObject {
    Q_OBJECT

public:
    explicit FileModel(std::shared_ptr<FileService> fileService, QObject* parent = nullptr);
    
    // File operations
    void uploadFile(const QString& filePath);
    void downloadFile(const QString& fileName, const QString& savePath);
    void deleteFile(const QString& fileName);
    void listFiles(int page = 1, int pageSize = 50);

    // Access control
    void grantAccess(const QString& fileName, const QString& username);
    void revokeAccess(const QString& fileName, const QString& username);
    void getUsersWithAccess(const QString& fileName);

signals:
    // Operation results
    void fileUploaded(bool success, const QString& fileName);
    void fileDownloaded(bool success, const QString& fileName);
    void fileDeleted(bool success, const QString& fileName);
    void fileListUpdated(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages);
    
    // Access control results
    void accessGranted(bool success, const QString& fileName, const QString& username);
    void accessRevoked(bool success, const QString& fileName, const QString& username);
    void usersWithAccessReceived(const QString& fileName, const QStringList& users);
    
    // Progress updates
    void uploadProgress(qint64 bytesSent, qint64 bytesTotal);
    void downloadProgress(qint64 bytesReceived, qint64 bytesTotal);
    
    // Errors
    void errorOccurred(const QString& error);

private slots:
    // File operation handlers
    void handleUploadComplete(bool success, const QString& fileName);
    void handleDownloadComplete(bool success, const QString& fileName);
    void handleDeleteComplete(bool success, const QString& fileName);
    void handleFileListReceived(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages);
    
    // Access control handlers
    void handleAccessGranted(bool success, const QString& fileName, const QString& username);
    void handleAccessRevoked(bool success, const QString& fileName, const QString& username);
    void handleUsersWithAccessReceived(const QString& fileName, const QStringList& users);
    
    // Progress handlers
    void handleUploadProgress(qint64 bytesSent, qint64 bytesTotal);
    void handleDownloadProgress(qint64 bytesReceived, qint64 bytesTotal);
    
    // Error handler
    void handleError(const QString& error);

private:
    std::shared_ptr<FileService> m_fileService;
}; 