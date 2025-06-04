#pragma once
#include "../ApiService.h"
#include <QObject>
#include <QString>

class IAuthService : public ApiService {
    Q_OBJECT
    
public:
    explicit IAuthService(QObject* parent = nullptr) : ApiService(parent) {}
    virtual ~IAuthService() = default;

    // Pure virtual methods that implementations must override
    virtual void login(const QString& username, const QString& authHash) = 0;
    virtual void registerUser(const QString& username,
                            const QString& authHash,
                            const QString& encryptedMEK,
                            const QString& authSalt1,
                            const QString& authSalt2,
                            const QString& encSalt,
                            const QString& mekIV,
                            const QString& mekTag) = 0;
    virtual void changePassword(const QString& username,
                              const QString& oldAuthHash,
                              const QString& newAuthHash,
                              const QString& newEncryptedMEK) = 0;
    virtual bool isInitialized() const override = 0;

signals:
    void loginCompleted(bool success, const QString& token = QString());
    void registrationCompleted(bool success);
    void passwordChangeCompleted(bool success);
}; 
