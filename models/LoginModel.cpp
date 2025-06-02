#include "LoginModel.h"
#include <QCryptographicHash>
#include <QUuid>

/**
 * @class LoginModel
 * @brief Manages login and registration operations.
 * @author jjola00
 *
 * This class handles user login and registration operations.
 */

LoginModel::LoginModel(IAuthService* authDb, QObject* parent)
    : QObject(parent), m_authDb(authDb) 
{
    connect(m_authDb, &IAuthService::loginCompleted,
            this, &LoginModel::handleLoginCompleted);

    connect(m_authDb, &IAuthService::registrationCompleted,
            this, &LoginModel::handleRegistrationCompleted);
}


void LoginModel::handleLoginCompleted(bool success, const QString& token) {
    if (success) {
        emit authSuccess();
    } else {
        emit authError("Login failed");
    }
}

void LoginModel::handleRegistrationCompleted(bool success) {
    if (success) {
        emit authSuccess();
    } else {
        emit authError("Registration failed");
    }
}

QString LoginModel::hashPassword(const QString& password, const QString& salt) const {
    return QCryptographicHash::hash(
        (password + salt).toUtf8(), 
        QCryptographicHash::Sha256
    ).toHex();
}

void LoginModel::login(const QString& username, const QString& password) {
    if (username.isEmpty() || password.isEmpty()) {
        emit authError("Credentials cannot be empty");
        return;
    }
    
    QString tempSalt = "static_salt"; 
    QString hashedPassword = hashPassword(password, tempSalt);
    
    m_authDb->login(username, hashedPassword);
}

void LoginModel::registerUser(const QString& username, 
                            const QString& password,
                            const QString& confirmPassword) {
    if (username.isEmpty() || password.isEmpty()) {
        emit authError("Fields cannot be empty");
        return;
    }
    
    if (password != confirmPassword) {
        emit authError("Passwords don't match");
        return;
    }
    
    QString authSalt = QUuid::createUuid().toString();
    QString encSalt = QUuid::createUuid().toString();
    
    QString authKey = hashPassword(password, authSalt);
    QString encryptedMEK = "mock_encrypted_key"; 
    
    m_authDb->registerUser(username, authSalt, encSalt, authKey, encryptedMEK);
}

void LoginModel::changePassword(const QString& username,
                              const QString& oldPassword,
                              const QString& newPassword,
                              const QString& confirmPassword) { //HAHAHAHA
    if (newPassword != confirmPassword) {
        emit authError("New passwords don't match");
        return;
    }
    
    QString oldAuthSalt = "retrieved_auth_salt";
    QString encSalt = "retrieved_enc_salt";

    QString oldAuthKey = hashPassword(oldPassword, oldAuthSalt);
    QString newAuthKey = hashPassword(newPassword, oldAuthSalt);
    QString newEncryptedMEK = "reencrypted_mock_key"; 
    
    m_authDb->changePassword(username, oldAuthKey, newAuthKey, newEncryptedMEK);
}