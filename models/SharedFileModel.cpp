#include "SharedFileModel.h"

SharedFileModel::SharedFileModel(std::shared_ptr<FileService> fileService, QObject* parent)
    : QObject(parent), m_fileService(fileService)
{
    // Connect shared file list signal - use the typed version
    connect(m_fileService.get(), &FileService::sharedFileListReceivedTyped,
            this, &SharedFileModel::handleSharedFileListReceived);
            
    // Connect download signals
    connect(m_fileService.get(), &FileService::downloadComplete,
            this, &SharedFileModel::handleDownloadComplete);
    connect(m_fileService.get(), &FileService::downloadProgress,
            this, &SharedFileModel::handleDownloadProgress);
            
    // Connect error signal
    connect(m_fileService.get(), &FileService::errorOccurred,
            this, &SharedFileModel::handleError);
}

void SharedFileModel::listSharedFiles(int page, int pageSize) {
    m_fileService->listSharedFiles(page, pageSize);
}

void SharedFileModel::downloadSharedFile(const QString& fileId, const QString& savePath) {
    m_fileService->downloadFile(fileId, savePath);
}

void SharedFileModel::handleSharedFileListReceived(const QList<MvcSharedFileInfo>& files, int totalFiles, int currentPage, int totalPages) {
    // No need for dynamic_cast anymore since we have proper typing
    emit sharedFileListUpdated(files, totalFiles, currentPage, totalPages);
}

void SharedFileModel::handleDownloadComplete(bool success, const QString& fileName) {
    emit fileDownloaded(success, fileName);
}

void SharedFileModel::handleDownloadProgress(const QString& fileName, qint64 bytesReceived, qint64 bytesTotal) {
    emit downloadProgress(bytesReceived, bytesTotal);
}

void SharedFileModel::handleError(const QString& error) {
    emit errorOccurred(error);
} 