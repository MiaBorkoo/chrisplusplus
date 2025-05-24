#ifndef LOGIN_MODEL_H
#define LOGIN_MODEL_H

#include <QString>
#include <QObject>
#include <vector>
#include "UserDatabase.h"

class LoginModel : public QObject {
    Q_OBJECT
public:
    explicit LoginModel(UserDatabase* userDatabase = nullptr, QObject* parent = nullptr);

    // User functions
    bool login(const std::string& username, const std::string& key);
    bool signUp(const std::string& username, const std::string& authSalt, const std::string& encSalt, const std::string& authKey, const std::string& encryptedMEK);
    bool changePassword(const std::string& username, const std::string& oldAuthKey, const std::string& newAuthKey, const std::string& newEncryptedMEK);
    bool validateCredentials(const std::string& username, const std::string& authKey);

    // File functions

    bool shareFile(const std::string& filename, const std::string& recipientUsername);
    bool revokeFile(const std::string& filename, const std::string& recipientUsername);
    bool deleteFile(const std::string& filename);
    bool uploadFile(const std::string& filename, const std::string& recipientUsername);

signals:
    void loginSuccess(const QString& username);
    void loginError(const QString& error);

private slots:
    void onUserLoggedIn(const QString& username);
    void onError(const QString& error);

private:
    UserDatabase* userDb;
};

#endif // LOGIN_MODEL_H
