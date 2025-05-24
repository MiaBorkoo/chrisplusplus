#include "UserDatabase.h"

UserDatabase::UserDatabase(AuthClient* client, QObject* parent)
    : Database(parent), authClient(client), userLoggedIn(false) {
    setConnectionString("API-based user authentication");
    setUpConnections();
    setConnectionStatus(authClient != nullptr);
}

bool UserDatabase::login(const QString& username, const QString& authKey) {
    if (!authClient) return false;
    currentUsername = username;
    authClient->login(username, authKey);
    return true;
}

bool UserDatabase::registerUser(const QString& username, const QString& authSalt,
                                const QString& encSalt, const QString& authKey,
                                const QString& encryptedMEK) {
    if (!authClient) return false;
    currentUsername = username;
    authClient->registerUser(username, authSalt, encSalt, authKey, encryptedMEK);
    return true;
}

bool UserDatabase::changePassword(const QString& username, const QString& oldAuthKey,
                                  const QString& newAuthKey, const QString& newEncryptedMEK) {
    if (!authClient) return false;
    currentUsername = username;
    authClient->changePassword(username, oldAuthKey, newAuthKey, newEncryptedMEK);
    return true;
}

bool UserDatabase::userExists(const QString& username) {
    if (!authClient) return false;
    if (responseCache.contains(username)) {
        return responseCache[username]->value("exists").toBool();
    }
    authClient->userExists(username);
    return false;
}
void UserDatabase::sync() {
    if (userLoggedIn && authClient && authClient->hasValidSession()) {
        emit syncCompleted(true);
    } else {
        emit syncCompleted(false);
    }
}

bool UserDatabase::isReady() const {
    return isConnectionActive() && userLoggedIn;
}

bool UserDatabase::validateData(const QJsonObject& data) {
    bool valid = data.contains("username") && isValidString(data["username"].toString(), 3);
    emit dataValidated(valid);
    return valid;
}

void UserDatabase::clearCache() {
    currentUsername.clear();
    userLoggedIn = false;
}

void UserDatabase::setUpConnections() {
    if (!authClient) return;

    connect(authClient, &AuthClient::loginCompleted,
            this, &UserDatabase::handleLoginResult);
    connect(authClient, &AuthClient::registrationCompleted,
            this, &UserDatabase::handleRegistrationResult);
    connect(authClient, &AuthClient::passwordChangeCompleted,
            this, &UserDatabase::handlePasswordChangeResult);

    connect(authClient, &AuthClient::loginFailed,
            this, &UserDatabase::handleAuthError);
    connect(authClient, &AuthClient::registrationFailed,
            this, &UserDatabase::handleAuthError);
    connect(authClient, &AuthClient::passwordChangeFailed,
            this, &UserDatabase::handleAuthError);

    connect(authClient, &AuthClient::sslErrorOccurred,
            this, &UserDatabase::handleAuthError);
}

void UserDatabase::handleLoginResult(bool success) {
    if (success) {
        userLoggedIn = true;
        emit userLoggedIn(currentUsername);
    } else {
        userLoggedIn = false;
        emit errorOccurred("Login failed.");
    }
}

void UserDatabase::handleRegistrationResult(bool success) {
    if (success) {
        emit userRegistered(currentUsername);
    } else {
        emit errorOccurred("Registration failed.");
    }
}

void UserDatabase::handlePasswordChangeResult(bool success) {
    if (success) {
        emit passwordChanged(currentUsername);
    } else {
        emit errorOccurred("Password change failed.");
    }
}

void UserDatabase::handleAuthError(const QString& error) {
    setError(error);
}
