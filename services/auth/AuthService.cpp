#include "AuthService.h"
#include <QJsonObject>

AuthService::AuthService(Client* client, QObject* parent)
    : IAuthService(parent), m_client(client) 
{
    // ✅ OLD-STYLE SIGNAL/SLOT (avoids Qt template issues)
    connect(m_client, SIGNAL(responseReceived(int, QJsonObject)), 
            this, SLOT(handleResponseReceived(int, QJsonObject)));

    connect(m_client, SIGNAL(networkError(QString)),
            this, SLOT(handleNetworkError(QString)));
}

void AuthService::login(const QString& username, const QString& authKey) {
    QJsonObject payload;
    payload["username"] = username;
    payload["auth_key"] = authKey;
    m_client->sendRequest("/login", "POST", payload);
}

void AuthService::registerUser(const QString& username, const QString& authSalt,
                              const QString& encSalt, const QString& authKey,
                              const QString& encryptedMEK) {
    QJsonObject payload;
    payload["username"] = username;
    payload["auth_salt"] = authSalt;
    payload["enc_salt"] = encSalt;
    payload["auth_key"] = authKey;
    payload["encrypted_mek"] = encryptedMEK;
    
    m_client->sendRequest("/register", "POST", payload);
}

void AuthService::changePassword(const QString& username, const QString& oldAuthKey,
                                const QString& newAuthKey, const QString& newEncryptedMEK) {
    QJsonObject payload;
    payload["username"] = username;
    payload["old_auth_key"] = oldAuthKey;
    payload["new_auth_key"] = newAuthKey;
    payload["new_encrypted_mek"] = newEncryptedMEK;
    
    m_client->sendRequest("/change_password", "POST", payload);
}

void AuthService::handleResponseReceived(int status, const QJsonObject& data) {
    QString endpoint = data.value("endpoint").toString();
    
    if (endpoint == "/login") {
        handleLoginResponse(status, data);
    } else if (endpoint == "/register") {
        handleRegisterResponse(status, data);
    } else if (endpoint == "/change_password") {
        handleChangePasswordResponse(status, data);
    }
}

void AuthService::handleNetworkError(const QString& error) {
    emit errorOccurred(error);
}

void AuthService::handleLoginResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200 && data.value("success").toBool());
    const QString token = data.value("token").toString();
    
    emit loginCompleted(success, token);
    if (success) {
        m_sessionToken = token;
    } else {
        emit errorOccurred(data.value("error").toString("Login failed. Please try again."));
    }
}

void AuthService::handleRegisterResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200 && data.value("success").toBool());
    emit registrationCompleted(success);
    if (!success) {
        emit errorOccurred(data.value("error").toString("Registration failed. Please try again."));
    }
}

void AuthService::handleChangePasswordResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200);
    emit passwordChangeCompleted(success);
    if (success) {
        invalidateSession(); 
    } else {
        emit errorOccurred(data.value("error").toString("Password change failed. Please try again."));
    }
}

void AuthService::invalidateSession() {
    m_sessionToken.clear();
    // Session invalidated, but no error
} 