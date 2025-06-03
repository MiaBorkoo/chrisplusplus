#pragma once
#include "../ApiService.h"
#include "../../network/Client.h"
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QSettings>
#include <memory>

class AuthService : public ApiService {
    Q_OBJECT
public:
    explicit AuthService(std::shared_ptr<Client> client = nullptr, QObject* parent = nullptr);
    ~AuthService() override = default;

    // Auth operations
    void login(const QString& username, const QString& authHash);
    void registerUser(const QString& username,
                     const QString& authHash,
                     const QString& encryptedMEK,
                     const QString& authSalt1,
                     const QString& authSalt2,
                     const QString& encSalt,
                     const QString& mekIV,
                     const QString& mekTag);
    void changePassword(const QString& username,
                       const QString& oldAuthHash,
                       const QString& newAuthHash,
                       const QString& newEncryptedMEK);

    // Implementation of ApiService
    bool isInitialized() const override {
        return m_client != nullptr;
    }

    // Session management
    QString sessionToken() const { return m_sessionToken; }
    bool hasActiveSession() const { return !m_sessionToken.isEmpty(); }
    void invalidateSession();

signals:
    void loginCompleted(bool success, const QString& token = QString());
    void registrationCompleted(bool success);
    void passwordChangeCompleted(bool success);

private slots:
    void handleResponseReceived(int status, const QJsonObject& data);
    void handleNetworkError(const QString& error);

private:
    std::shared_ptr<Client> m_client;
    QString m_sessionToken;
    QScopedPointer<QSettings> m_settings;
    
    void handleLoginResponse(int status, const QJsonObject& data);
    void handleRegisterResponse(int status, const QJsonObject& data);
    void handleChangePasswordResponse(int status, const QJsonObject& data);
}; 
