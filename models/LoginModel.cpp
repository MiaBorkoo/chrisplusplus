#include "LoginModel.h"
#include <QCryptographicHash>
#include <QUuid>
#include "../crypto/KeyDerivation.h"
#include "../crypto/MEKGenerator.h"
#include "../crypto/MEKWrapper.h"

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
    // OLD-STYLE SIGNAL/SLOT 
    connect(m_authDb, SIGNAL(loginCompleted(bool, QString)),
            this, SLOT(handleLoginCompleted(bool, QString)));
            
    connect(m_authDb, SIGNAL(registrationCompleted(bool)),
            this, SLOT(handleRegistrationCompleted(bool)));
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

    // 1. Generate salts
    KeyDerivation kd;
    std::vector<uint8_t> authSalt = kd.generateSalt();
    std::vector<uint8_t> encSalt = kd.generateSalt();

    // 2. Derive keys from password and salts
    DerivedKeys keys = kd.deriveKeysFromPassword(password.toStdString(), authSalt, encSalt);

    // 3. Generate a random MEK
    std::vector<unsigned char> mek = generateMEK();

    // 4. Encrypt the MEK with the MEK Wrapper Key
    std::vector<uint8_t> mekWrapperKey(keys.mekWrapperKey.begin(), keys.mekWrapperKey.end());
    EncryptedMEK encrypted = encryptMEKWithWrapperKey(mek, mekWrapperKey);

    // 5. Prepare data to send to server (Base64 encode all binary fields)
    QString authSaltB64 = QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(authSalt.data()), authSalt.size()).toBase64());
    QString encSaltB64 = QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(encSalt.data()), encSalt.size()).toBase64());
    QString authKeyB64 = QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(keys.serverAuthKey.data()), keys.serverAuthKey.size()).toBase64());
    QString encryptedMEKB64 = QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(encrypted.ciphertext.data()), encrypted.ciphertext.size()).toBase64());
    QString mekIVB64 = QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(encrypted.iv.data()), encrypted.iv.size()).toBase64());
    QString mekTagB64 = QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(encrypted.tag.data()), encrypted.tag.size()).toBase64());

    // 6. Call AuthService to register user
    m_authDb->registerUser(username, authSaltB64, encSaltB64, authKeyB64, encryptedMEKB64 /*, mekIVB64, mekTagB64 if you extend the API */);
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