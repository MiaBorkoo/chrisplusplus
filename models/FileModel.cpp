#include "FileModel.h"

FileModel::FileModel(std::shared_ptr<FileService> fileService, QObject* parent)
    : QObject(parent), m_fileService(fileService)
{
    // Connect file operation signals
    connect(m_fileService.get(), &FileService::uploadComplete,
            this, &FileModel::handleUploadComplete);
    connect(m_fileService.get(), &FileService::downloadComplete,
            this, &FileModel::handleDownloadComplete);
    connect(m_fileService.get(), &FileService::deleteComplete,
            this, &FileModel::handleDeleteComplete);
    connect(m_fileService.get(), &FileService::fileListReceived,
            this, &FileModel::handleFileListReceived);
            
    // Connect access control signals
    connect(m_fileService.get(), &FileService::accessGranted,
            this, &FileModel::handleAccessGranted);
    connect(m_fileService.get(), &FileService::accessRevoked,
            this, &FileModel::handleAccessRevoked);
    connect(m_fileService.get(), &FileService::usersWithAccessReceived,
            this, &FileModel::handleUsersWithAccessReceived);
            
    // Connect progress signals
    connect(m_fileService.get(), &FileService::uploadProgress,
            this, &FileModel::handleUploadProgress);
    connect(m_fileService.get(), &FileService::downloadProgress,
            this, &FileModel::handleDownloadProgress);
            
    // Connect error signal
    connect(m_fileService.get(), &FileService::errorOccurred,
            this, &FileModel::handleError);
}

// File operations
void FileModel::uploadFile(const QString& filePath) {
    m_fileService->uploadFile(filePath);
}

void FileModel::downloadFile(const QString& fileName, const QString& savePath) {
    m_fileService->downloadFile(fileName, savePath);
}

void FileModel::deleteFile(const QString& fileName) {
    m_fileService->deleteFile(fileName);
}

void FileModel::listFiles(int page, int pageSize) {
    m_fileService->listFiles(page, pageSize);
}

// Access control operations
void FileModel::grantAccess(const QString& fileName, const QString& username) {
    m_fileService->grantAccess(fileName, username);
}

void FileModel::revokeAccess(const QString& fileName, const QString& username) {
    m_fileService->revokeAccess(fileName, username);
}

void FileModel::getUsersWithAccess(const QString& fileName) {
    m_fileService->getUsersWithAccess(fileName);
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

// Access control handlers
void FileModel::handleAccessGranted(bool success, const QString& fileName, const QString& username) {
    emit accessGranted(success, fileName, username);
}

void FileModel::handleAccessRevoked(bool success, const QString& fileName, const QString& username) {
    emit accessRevoked(success, fileName, username);
}

void FileModel::handleUsersWithAccessReceived(const QString& fileName, const QStringList& users) {
    emit usersWithAccessReceived(fileName, users);
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