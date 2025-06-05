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

signals:
    // Operation results
    void fileUploaded(bool success, const QString& fileName);
    void fileDownloaded(bool success, const QString& fileName);
    void fileDeleted(bool success, const QString& fileName);
    void fileListUpdated(const QList<MvcFileInfo>& files, int totalFiles, int currentPage, int totalPages);
    
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
    void handleFileListReceived(const QList<MvcFileInfo>& files, int totalFiles, int currentPage, int totalPages);
    
    // Progress handlers
    void handleUploadProgress(const QString& fileName, qint64 bytesSent, qint64 bytesTotal);
    void handleDownloadProgress(const QString& fileName, qint64 bytesReceived, qint64 bytesTotal);
    
    // Error handler
    void handleError(const QString& error);

private:
    std::shared_ptr<FileService> m_fileService;
}; 