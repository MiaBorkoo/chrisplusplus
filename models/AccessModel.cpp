#include "AccessModel.h"

AccessModel::AccessModel(std::shared_ptr<FileService> fileService, QObject* parent)
    : QObject(parent), m_fileService(fileService)
{
    // Connect access control signals
    connect(m_fileService.get(), &FileService::accessGranted,
            this, &AccessModel::handleAccessGranted);
    connect(m_fileService.get(), &FileService::accessRevoked,
            this, &AccessModel::handleAccessRevoked);
    connect(m_fileService.get(), &FileService::usersWithAccessReceived,
            this, &AccessModel::handleUsersWithAccessReceived);
            
    // Connect error signal
    connect(m_fileService.get(), &FileService::errorOccurred,
            this, &AccessModel::handleError);
}

void AccessModel::grantAccess(const QString& fileName, const QString& username) {
    m_fileService->grantAccess(fileName, username);
}

void AccessModel::revokeAccess(const QString& fileName, const QString& username) {
    m_fileService->revokeAccess(fileName, username);
}

void AccessModel::getUsersWithAccess(const QString& fileName) {
    m_fileService->getUsersWithAccess(fileName);
}

void AccessModel::handleAccessGranted(bool success, const QString& fileName, const QString& username) {
    emit accessGranted(success, fileName, username);
}

void AccessModel::handleAccessRevoked(bool success, const QString& fileName, const QString& username) {
    emit accessRevoked(success, fileName, username);
}

void AccessModel::handleUsersWithAccessReceived(const QString& fileName, const QStringList& users) {
    emit usersWithAccessReceived(fileName, users);
}

void AccessModel::handleError(const QString& error) {
    emit errorOccurred(error);
} 