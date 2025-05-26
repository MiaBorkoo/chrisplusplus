#pragma once
#include "IAuthService.h"
#include "../../network/Client.h"
#include <QJsonObject>

class AuthService : public IAuthService {
    Q_OBJECT
public:
    explicit AuthService(Client* client = nullptr, QObject* parent = nullptr);
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

    QString sessionToken() const { return m_sessionToken; }
    bool hasActiveSession() const { return !m_sessionToken.isEmpty(); }
    
    void invalidateSession();

private slots:
    void handleResponseReceived(int status, const QJsonObject& data);
    void handleNetworkError(const QString& error);

private:
    Client* m_client;
    QString m_sessionToken;
    
    void handleLoginResponse(int status, const QJsonObject& data);
    void handleRegisterResponse(int status, const QJsonObject& data);
    void handleChangePasswordResponse(int status, const QJsonObject& data);
}; 