#pragma once
#include <QObject>
#include <QString>
#include "../services/files/FileService.h"
#include <memory>

class SharedFileModel : public QObject {
    Q_OBJECT

public:
    explicit SharedFileModel(std::shared_ptr<FileService> fileService, QObject* parent = nullptr);
    
    // Shared file operations
    void listSharedFiles(int page = 1, int pageSize = 50);
    void downloadSharedFile(const QString& fileName, const QString& savePath);

signals:
    // Operation results
    void sharedFileListUpdated(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages);
    void fileDownloaded(bool success, const QString& fileName);
    
    // Progress updates
    void downloadProgress(qint64 bytesReceived, qint64 bytesTotal);
    
    // Errors
    void errorOccurred(const QString& error);

private slots:
    void handleSharedFileListReceived(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages);
    void handleDownloadComplete(bool success, const QString& fileName);
    void handleDownloadProgress(const QString& fileName, qint64 bytesReceived, qint64 bytesTotal);
    void handleError(const QString& error);

private:
    std::shared_ptr<FileService> m_fileService;
}; 