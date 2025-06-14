#pragma once
#include <QObject>
#include <QString>

class IAuthService : public QObject {
    Q_OBJECT
    
public:
    explicit IAuthService(QObject* parent = nullptr) : QObject(parent) {}
    virtual ~IAuthService() = default;

    // Pure virtual methods that implementations must override
    virtual void login(const QString& username, const QString& authKey) = 0;
    virtual void registerUser(const QString& username, const QString& authSalt,
                             const QString& encSalt, const QString& authKey,
                             const QString& encryptedMEK) = 0;
    virtual void changePassword(const QString& username, const QString& oldAuthKey,
                               const QString& newAuthKey, const QString& newEncryptedMEK) = 0;

signals:
    void loginCompleted(bool success, const QString& token = QString());
    void registrationCompleted(bool success);
    void passwordChangeCompleted(bool success);
    void errorOccurred(const QString& error);
}; 
