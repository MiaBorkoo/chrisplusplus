#pragma once
#include "IAuthService.h"
#include "../../network/AuthClient.h"

class AuthService : public IAuthService {
    Q_OBJECT
public:
    explicit AuthService(AuthClient* client = nullptr, QObject* parent = nullptr);
    ~AuthService() override = default;

    // Interface implementations
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

    QString sessionToken() const { return m_sessionToken; }
    bool hasActiveSession() const { return !m_sessionToken.isEmpty(); }

private:
    AuthClient* m_client;
    QString m_sessionToken;
    
    void handleLoginResponse(int status, const QJsonObject& data);
    void handleRegisterResponse(int status, const QJsonObject& data);
    void handleChangePasswordResponse(int status, const QJsonObject& data);
    void handleUserExistsResponse(int status, const QJsonObject& data);

    void clearSession(); 
};