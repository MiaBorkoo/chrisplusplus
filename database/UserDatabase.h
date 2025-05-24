#ifndef USER_DATABASE_H
#define USER_DATABASE_H

#include "Database.h"
#include "AuthClient.h"

class UserDatabase : public Database {
    Q_OBJECT

public:
    explicit UserDatabase(AuthClient* client, QObject* parent = nullptr)
        : Database(parent), authClient(client) {}

    void login(const QString& username, const QString& authKey);
    void registerUser(const QString& username, const QString& authSalt,
                      const QString& encSalt, const QString& authKey,
                      const QString& encryptedMEK);
    void changePassword(const QString& username, const QString& oldAuthKey,
                        const QString& newAuthKey, const QString& newEncryptedMEK);

    void sync() override {} // not needed now but fulfills base

private:
    AuthClient* authClient;
};

#endif // USER_DATABASE_H
