#pragma once
#include "AuthDatabaseInterface.h"
#include "../../network/AuthClient.h"

class AuthDatabase : public AuthDatabaseInterface {
    Q_OBJECT
public:
    explicit AuthDatabase(AuthClient* client, QObject* parent = nullptr);
    
    // AuthDatabaseInterface implementation
    bool isReady() const override;
    void clear() override;
    void login(const QString& username, const QString& authKey) override;
    void registerUser(const QString& username,
                    const QString& authSalt,
                    const QString& encSalt,
                    const QString& authKey,
                    const QString& encryptedMEK) override;

private:
    AuthClient* m_client;
    QString m_sessionToken;

private slots:
    void handleLoginResponse(int status, const QJsonObject& data);
};