#include "AuthService.h"
#include "otp/TOTP.h"          
#include <QJsonObject>
#include <QSettings>           


/**
 * @class AuthService
 * @brief Handles authentication operations.
 * @author jjola00
 *
 * This class handles authentication operations.
 */

AuthService::AuthService(Client* client, QObject* parent)
    : IAuthService(parent), m_client(client), m_settings(new QSettings(this))  
{
    connect(m_client, SIGNAL(responseReceived(int, QJsonObject)), 
            this, SLOT(handleResponseReceived(int, QJsonObject)));

    connect(m_client, SIGNAL(networkError(QString)),
            this, SLOT(handleNetworkError(QString)));
}

void AuthService::login(const QString& username, const QString& authHash) {
    QJsonObject payload;
    payload["username"] = username;
    payload["auth_hash"] = authHash;
    
    const QString secretB32 = m_settings->value("totp/secret").toString();
    if (!secretB32.isEmpty()) {                 
        TOTP totp(secretB32.toStdString());  
        const QString otp = QString::fromStdString(totp.generate());  
        payload["otp"] = otp;                   
    }
    m_client->sendRequest("/login", "POST", payload);
}

void AuthService::registerUser(const QString& username,
                             const QString& authHash,
                             const QString& encryptedMEK,
                             const QString& authSalt1,
                             const QString& authSalt2,
                             const QString& encSalt,
                             const QString& mekIV,  
                             const QString& mekTag) {
    QJsonObject payload;
    payload["username"] = username;
    payload["auth_hash"] = authHash;
    payload["encrypted_mek"] = encryptedMEK;
    payload["auth_salt1"] = authSalt1;
    payload["auth_salt2"] = authSalt2;
    payload["enc_salt"] = encSalt;
    payload["mek_iv"] = mekIV;
    payload["mek_tag"] = mekTag;
    
    m_client->sendRequest("/register", "POST", payload);
}

void AuthService::changePassword(const QString& username,
                               const QString& oldAuthHash,
                               const QString& newAuthHash,
                               const QString& newEncryptedMEK) {
    QJsonObject payload;
    payload["username"] = username;
    payload["old_auth_hash"] = oldAuthHash;
    payload["new_auth_hash"] = newAuthHash;
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
    reportError(error);
}

void AuthService::handleLoginResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200 && data.value("success").toBool());
    const QString token = data.value("token").toString();
    
    emit loginCompleted(success, token);
    if (success) {
        m_sessionToken = token;
    } else {
        reportError(data.value("error").toString("Login failed. Please try again."));
    }
}

void AuthService::handleRegisterResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200 && data.value("success").toBool());
    emit registrationCompleted(success);
    if (!success) {
        reportError(data.value("error").toString("Registration failed. Please try again."));
    }
}

void AuthService::handleChangePasswordResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200);
    emit passwordChangeCompleted(success);
    if (success) {
        invalidateSession(); 
    } else {
        reportError(data.value("error").toString("Password change failed. Please try again."));
    }
}

void AuthService::invalidateSession() {
    m_sessionToken.clear();
} 
