#include "SharedFileModel.h"

SharedFileModel::SharedFileModel(std::shared_ptr<FileService> fileService, QObject* parent)
    : QObject(parent), m_fileService(fileService)
{
    // Connect shared file list signal
    connect(m_fileService.get(), &FileService::sharedFileListReceived,
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

void SharedFileModel::downloadSharedFile(const QString& fileName, const QString& savePath) {
    m_fileService->downloadFile(fileName, savePath);
}

void SharedFileModel::handleSharedFileListReceived(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages) {
    QList<FileInfo> processedFiles;
    for (const FileInfo& file : files) {
        // Check if this is a SharedFileInfo
        const SharedFileInfo* sharedInfo = dynamic_cast<const SharedFileInfo*>(&file);
        if (sharedInfo) {
            SharedFileInfo newInfo;
            newInfo.name = file.name;
            newInfo.size = file.size;
            newInfo.uploadDate = file.uploadDate;
            newInfo.acl = file.acl;
            newInfo.sharedBy = sharedInfo->sharedBy;
            processedFiles.append(newInfo);
        } else {
            processedFiles.append(file);
        }
    }
    emit sharedFileListUpdated(processedFiles, totalFiles, currentPage, totalPages);
}

void SharedFileModel::handleDownloadComplete(bool success, const QString& fileName) {
    emit fileDownloaded(success, fileName);
}

void SharedFileModel::handleDownloadProgress(qint64 bytesReceived, qint64 bytesTotal) {
    emit downloadProgress(bytesReceived, bytesTotal);
}

void SharedFileModel::handleError(const QString& error) {
    emit errorOccurred(error);
} 