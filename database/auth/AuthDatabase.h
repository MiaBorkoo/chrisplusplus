#pragma once
#include "AuthDatabaseInterface.h"
#include "../../network/AuthClient.h"

class AuthDatabase : public AuthDatabaseInterface {
    Q_OBJECT
public:
    explicit AuthDatabase(AuthClient* client = nullptr, QObject* parent = nullptr);
    
    bool isReady() const override;
    void clear() override;  
    void login(const QString& username, const QString& authKey) override;
    void registerUser(const QString& username,
                    const QString& authSalt,
                    const QString& encSalt,
                    const QString& authKey,
                    const QString& encryptedMEK) override;
    void changePassword(const QString& username,
                        const QString& oldAuthKey,
                        const QString& newAuthKey,
                        const QString& newEncryptedMEK) override;
    void checkUserExists(const QString& username) override;

private:
    AuthClient* m_client = nullptr;
    QString m_sessionToken;
    
private slots:
    void handleLoginResponse(int status, const QJsonObject& data);
    void handleError(const QString& error);
    void handleRegisterResponse(int status, const QJsonObject& data);
    void handleChangePasswordResponse(int status, const QJsonObject& data);
    void handleUserExistsResponse(int status, const QJsonObject& data);
};