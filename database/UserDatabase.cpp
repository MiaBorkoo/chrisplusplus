// UserDatabase.cpp
#include "UserDatabase.h"

void UserDatabase::login(const QString& username, const QString& authKey) {
    authClient->login(username, authKey);
}

void UserDatabase::registerUser(const QString& username, const QString& authSalt,
                                const QString& encSalt, const QString& authKey,
                                const QString& encryptedMEK) {
    authClient->registerUser(username, authSalt, encSalt, authKey, encryptedMEK);
}

void UserDatabase::changePassword(const QString& username, const QString& oldAuthKey,
                                  const QString& newAuthKey, const QString& newEncryptedMEK) {
    authClient->changePassword(username, oldAuthKey, newAuthKey, newEncryptedMEK);
}
