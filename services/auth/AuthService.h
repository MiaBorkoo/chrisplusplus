#pragma once
#include "IAuthService.h"
#include "../../network/Client.h"
#include <QJsonObject>
#include <QSettings>   

class AuthService : public IAuthService {
    Q_OBJECT
public:
    explicit AuthService(Client* client = nullptr, QObject* parent = nullptr);
    ~AuthService() override = default;

    // Interface implementations
    void login(const QString& username, const QString& authHash) override;
    void registerUser(const QString& username,
                     const QString& authHash,
                     const QString& encryptedMEK,
                     const QString& authSalt1,
                     const QString& authSalt2,
                     const QString& encSalt,
                     const QString& mekIV,
                     const QString& mekTag) override;
    void changePassword(const QString& username,
                       const QString& oldAuthHash,
                       const QString& newAuthHash,
                       const QString& newEncryptedMEK) override;
    bool isInitialized() const override {
        return m_client != nullptr;
    }

    QString sessionToken() const { return m_sessionToken; }
    bool hasActiveSession() const { return !m_sessionToken.isEmpty(); }
    
    void invalidateSession();

private slots:
    void handleResponseReceived(int status, const QJsonObject& data);
    void handleNetworkError(const QString& error);

private:
    Client* m_client;
    QString m_sessionToken;
    QScopedPointer<QSettings> m_settings;
    
    void handleLoginResponse(int status, const QJsonObject& data);
    void handleRegisterResponse(int status, const QJsonObject& data);
    void handleChangePasswordResponse(int status, const QJsonObject& data);
}; 
