#include "FileModel.h"

FileModel::FileModel(std::shared_ptr<FileService> fileService, QObject* parent)
    : QObject(parent), m_fileService(fileService)
{
    // Connect file service signals to model slots
    connect(m_fileService.get(), &FileService::uploadComplete,
            this, &FileModel::handleUploadComplete);
    connect(m_fileService.get(), &FileService::downloadComplete,
            this, &FileModel::handleDownloadComplete);
    connect(m_fileService.get(), &FileService::deleteComplete,
            this, &FileModel::handleDeleteComplete);
    connect(m_fileService.get(), &FileService::fileListReceived,
            this, &FileModel::handleFileListReceived);
    connect(m_fileService.get(), &FileService::errorOccurred,
            this, &FileModel::handleError);
}

// File operations
void FileModel::uploadFile(const QString& filePath)
{
    m_fileService->uploadFile(filePath);
}

void FileModel::downloadFile(const QString& fileName, const QString& savePath)
{
    m_fileService->downloadFile(fileName, savePath);
}

void FileModel::deleteFile(const QString& fileName) {
    m_fileService->deleteFile(fileName);
}

void FileModel::listFiles(int page, int pageSize) {
    m_fileService->listFiles(page, pageSize);
}

// File operation handlers
void FileModel::handleUploadComplete(bool success, const QString& fileName) {
    emit fileUploaded(success, fileName);
}

void FileModel::handleDownloadComplete(bool success, const QString& fileName) {
    emit fileDownloaded(success, fileName);
}

void FileModel::handleDeleteComplete(bool success, const QString& fileName) {
    emit fileDeleted(success, fileName);
}

void FileModel::handleFileListReceived(const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages) {
    emit fileListUpdated(files, totalFiles, currentPage, totalPages);
}

// Progress handlers
void FileModel::handleUploadProgress(qint64 bytesSent, qint64 bytesTotal) {
    emit uploadProgress(bytesSent, bytesTotal);
}

void FileModel::handleDownloadProgress(qint64 bytesReceived, qint64 bytesTotal) {
    emit downloadProgress(bytesReceived, bytesTotal);
}

// Error handler
void FileModel::handleError(const QString& error) {
    emit errorOccurred(error);
} 