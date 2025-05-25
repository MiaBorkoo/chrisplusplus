#include "AuthDatabase.h"

AuthDatabase::AuthDatabase(AuthClient* client, QObject* parent)
    : AuthDatabaseInterface(parent), m_client(client) {
    connect(m_client, &AuthClient::responseReceived,
            this, &AuthDatabase::handleLoginResponse);
    connect(m_client, &AuthClient::errorOccurred,
            this, &AuthDatabase::handleError);
    connect(m_client, &AuthClient::responseReceived,
            this, &AuthDatabase::handleRegisterResponse);
    connect(m_client, &AuthClient::responseReceived,
            this, &AuthDatabase::handleChangePasswordResponse);
    connect(m_client, &AuthClient::responseReceived,
            this, &AuthDatabase::handleUserExistsResponse);
}

void AuthDatabase::login(const QString& username, const QString& authKey) {
    QJsonObject data{
        {"username", username},
        {"auth_key", authKey}
    };
    m_client->sendRequest("/login", "POST", data);
}

void AuthDatabase::handleLoginResponse(int status, const QJsonObject& data) {
    if (status == 200) {
        m_sessionToken = data["token"].toString();
        emit loginCompleted(true, m_sessionToken);
    } else {
        emit errorOccurred(data["error"].toString());
        emit loginCompleted(false, "");
    }
}

void AuthDatabase::registerUser(const QString& username,
                                const QString& authSalt,
                                const QString& encSalt,
                                const QString& authKey,
                                const QString& encryptedMEK) {
    QJsonObject data{
        {"username", username},
        {"auth_salt", authSalt},
        {"enc_salt", encSalt},
        {"auth_key", authKey},
        {"encrypted_mek", encryptedMEK}
    };
    m_client->sendRequest("/register", "POST", data);
}
void AuthDatabase::handleRegisterResponse(int status, const QJsonObject& data) {
    if (status == 201) {
        emit registrationCompleted(true);
    } else {
        emit errorOccurred(data["error"].toString());
        emit registrationCompleted(false);
    }
}
void AuthDatabase::changePassword(const QString& username,
                                  const QString& oldAuthKey,
                                  const QString& newAuthKey,
                                  const QString& newEncryptedMEK) {
    QJsonObject data{
        {"username", username},
        {"auth_key", oldAuthKey},
        {"new_auth_key", newAuthKey},
        {"new_encrypted_mek", newEncryptedMEK}
    };
    m_client->sendRequest("/change_password", "POST", data);
}

void AuthDatabase::handleChangePasswordResponse(int status, const QJsonObject& data) {
    if (status == 200) {
        emit passwordChangeCompleted(true);
    } else {
        emit errorOccurred(data["error"].toString());
        emit passwordChangeCompleted(false);
    }
}

void AuthDatabase::checkUserExists(const QString& username) {
    QJsonObject data{
        {"username", username}
    };
    m_client->sendRequest("/check_user_exists", "POST", data);
}

void AuthDatabase::handleUserExistsResponse(int status, const QJsonObject& data) {
    if (status == 200) {
        emit userExistsChecked(true);
    } else {
        emit errorOccurred(data["error"].toString());
        emit userExistsChecked(false);
    }
}