#include "AuthService.h"

AuthService::AuthService(AuthClient* client, QObject* parent)
    : IAuthService(parent), m_client(client) 
{
    connect(m_client, &AuthClient::responseReceived, 
           this, [this](int status, const QJsonObject& data) {
        const QString endpoint = data["endpoint"].toString();
        
        if (endpoint == "/login") {
            handleLoginResponse(status, data);
        }
        else if (endpoint == "/register") {
            handleRegisterResponse(status, data);
        }
        else if (endpoint == "/change_password") {
            handleChangePasswordResponse(status, data);
        }
        else if (endpoint == "/check_user_exists") {
            handleUserExistsResponse(status, data);
        }
    });

    connect(m_client, &AuthClient::errorOccurred,
            this, &AuthService::errorOccurred);
}

void AuthService::login(const QString& username, const QString& authKey) {
    QJsonObject payload{
        {"username", username},
        {"auth_key", authKey},
        {"endpoint", "/login"} 
    };
    m_client->sendRequest("/login", "POST", payload);
}

void AuthService::registerUser(const QString& username,
                             const QString& authSalt,
                             const QString& encSalt,
                             const QString& authKey,
                             const QString& encryptedMEK) {
    QJsonObject payload{
        {"username", username},
        {"auth_salt", authSalt},
        {"enc_salt", encSalt},
        {"auth_key", authKey},
        {"encrypted_mek", encryptedMEK},
        {"endpoint", "/register"}
    };
    m_client->sendRequest("/register", "POST", payload);
}

void AuthService::changePassword(const QString& username,
                               const QString& oldAuthKey,
                               const QString& newAuthKey,
                               const QString& newEncryptedMEK) {
    QJsonObject payload{
        {"username", username},
        {"old_auth_key", oldAuthKey},
        {"new_auth_key", newAuthKey},
        {"new_encrypted_mek", newEncryptedMEK},
        {"endpoint", "/change_password"}
    };
    m_client->sendRequest("/change_password", "POST", payload);
}

void AuthService::checkUserExists(const QString& username) {
    QJsonObject payload{
        {"username", username},
        {"endpoint", "/check_user_exists"}
    };
    m_client->sendRequest("/check_user_exists", "POST", payload);
}

void AuthService::handleLoginResponse(int status, const QJsonObject& data) {
    if (status == 200) {
        m_sessionToken = data["token"].toString();
        emit loginCompleted(true, m_sessionToken);
    } else {
        emit loginCompleted(false, "");
        emit errorOccurred(data.value("error").toString("Login failed"));
    }
}

void AuthService::handleRegisterResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200);
    emit registrationCompleted(success);
    if (!success) {
        emit errorOccurred(data.value("error").toString("Registration failed"));
    }
}

void AuthService::handleChangePasswordResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200);
    emit passwordChangeCompleted(success);
    if (!success) {
        emit errorOccurred(data.value("error").toString("Password change failed"));
    }
}

void AuthService::handleUserExistsResponse(int status, const QJsonObject& data) {
    const bool exists = (status == 200);
    emit userExistsChecked(exists);
    if (!exists) {
        emit errorOccurred(data.value("error").toString("User check failed"));
    }
}