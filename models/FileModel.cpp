#include "FileModel.h"
#include <iostream>

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
    connect(m_fileService.get(), &FileService::uploadProgress,
            this, &FileModel::handleUploadProgress);
    connect(m_fileService.get(), &FileService::downloadProgress,
            this, &FileModel::handleDownloadProgress);
}

// File operations
void FileModel::uploadFile(const QString& filePath)
{
    std::cout << "📋 FILEMODEL: uploadFile called with path: " << filePath.toStdString() << std::endl;
    m_fileService->uploadFile(filePath);
    std::cout << " FILEMODEL: m_fileService->uploadFile call completed" << std::endl;
}

void FileModel::downloadFile(const QString& fileId, const QString& savePath)
{
    m_fileService->downloadFile(fileId, savePath);
}

void FileModel::deleteFile(const QString& fileId) {
    m_fileService->deleteFile(fileId);
}

void FileModel::listFiles(int page, int pageSize) {
    std::cout << "FileModel::listFiles called with page=" << page << ", pageSize=" << pageSize << std::endl;
    m_fileService->listFiles(page, pageSize);
    std::cout << "FileModel::listFiles - called m_fileService->listFiles()" << std::endl;
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

void FileModel::handleFileListReceived(const QList<MvcFileInfo>& files, int totalFiles, int currentPage, int totalPages) {
    emit fileListUpdated(files, totalFiles, currentPage, totalPages);
}

// Progress handlers
void FileModel::handleUploadProgress(const QString& fileName, qint64 bytesSent, qint64 bytesTotal) {
    emit uploadProgress(bytesSent, bytesTotal);
}

void FileModel::handleDownloadProgress(const QString& fileName, qint64 bytesReceived, qint64 bytesTotal) {
    emit downloadProgress(bytesReceived, bytesTotal);
}

// Error handler
void FileModel::handleError(const QString& error) {
    emit errorOccurred(error);
} 