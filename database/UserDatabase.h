#ifndef USER_DATABASE_H
#define USER_DATABASE_H

#include "Database.h"
#include "AuthClient.h"

class UserDatabase : public Database {
    Q_OBJECT

public:
    explicit UserDatabase(AuthClient* client, QObject* parent = nullptr)
        : Database(parent), authClient(client) {}

    bool login(const QString& username, const QString& authKey);
    bool signUp(const QString& username, const QString& authSalt, const QString& encSalt, const QString& authKey, const QString& encryptedMEK);
    bool changePassword(const QString& username, const QString& oldAuthKey, const QString& newAuthKey, const QString& newEncryptedMEK);
    bool userExists(const QString& username);
    void sync() override;
    bool isReady() const override;
    bool validateData(const QJsonObject& data) override;
    void clearCache() override;

private slots:
    void handleLoginResult(bool success);
    void handleRegistrationResult(bool success);
    void handlePasswordChangeResult(bool success);
    void handleAuthError(const QString& error);
    void handleUserExistsResult(bool exists);

private:
    AuthClient* authClient = nullptr;
    QString currentUsername;
    bool userLoggedIn;
    void setUpConnections();

signals:
    void userLoggedIn(const QString& username);
    void userLoggedOut();
    void userRegistered(const QString& username);
    void passwordChanged(const QString& username);
};

#endif // USER_DATABASE_H