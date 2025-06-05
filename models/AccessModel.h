#pragma once
#include <QObject>
#include <QString>
#include "../services/files/FileService.h"
#include <memory>

class AccessModel : public QObject {
    Q_OBJECT

public:
    explicit AccessModel(std::shared_ptr<FileService> fileService, QObject* parent = nullptr);
    
    // Access control operations
    void grantAccess(const QString& fileName, const QString& username);
    void revokeAccess(const QString& fileName, const QString& username);
    void getUsersWithAccess(const QString& fileName);

signals:
    // Access control results
    void accessGranted(bool success, const QString& fileName, const QString& username);
    void accessRevoked(bool success, const QString& fileName, const QString& username);
    void usersWithAccessReceived(const QString& fileId, const QStringList& users);
    
    // Errors
    void errorOccurred(const QString& error);

private slots:
    // Access control handlers
    void handleAccessGranted(bool success, const QString& fileName, const QString& username);
    void handleAccessRevoked(bool success, const QString& fileName, const QString& username);
    void handleUsersWithAccessReceived(const QString& fileId, const QStringList& users);
    void handleError(const QString& error);

private:
    std::shared_ptr<FileService> m_fileService;
}; 