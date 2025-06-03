#include "LoginModel.h"
#include "../crypto/KeyDerivation.h"
#include "../crypto/MEKGenerator.h"
#include "../crypto/WrappedMEK.h"
#include "../crypto/AuthHash.h"

/**
 * @class LoginModel
 * @brief Manages login and registration operations.
 * @author jjola00
 *
 * This class handles user login and registration operations.
 */

template <size_t N>
QString toBase64String(const std::array<uint8_t, N>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

QString toBase64String(const std::vector<uint8_t>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

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


void LoginModel::login(const QString& username, const QString& password) {
    if (username.isEmpty() || password.isEmpty()) {
        emit authError("Credentials cannot be empty");
        return;
    }
    
    emit authError("Login not implemented with new crypto flow");
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

    // 2.5. Hash the serverAuthKey
    std::vector<uint8_t> authSalt2 = AuthHash::generateSalt(16);

    std::vector<uint8_t> serverAuthKeyVec(keys.serverAuthKey.begin(), keys.serverAuthKey.end());//converting auth key from std::array to std::vector 

    // this computes the authentication hash using the server authkey and the new salt
    std::vector<uint8_t> authHash = AuthHash::computeAuthHash(serverAuthKeyVec, authSalt2);

    // 3. Generate a random MEK
    std::vector<unsigned char> mek = generateMEK();

    // 4. Encrypt the MEK with the MEK Wrapper Key
    std::vector<uint8_t> mekWrapperKey(keys.mekWrapperKey.begin(), keys.mekWrapperKey.end());
    EncryptedMEK encrypted = encryptMEKWithWrapperKey(mek, mekWrapperKey);

    // 5. Prepare data to send to server (Base64 encode all binary fields)
    QString authSaltB64 = toBase64String(authSalt);
    QString encSaltB64 = toBase64String(encSalt);
    QString authKeyB64 = toBase64String(keys.serverAuthKey);
    QString authHashB64 = toBase64String(authHash);
    QString encryptedMEKB64 = toBase64String(encrypted.ciphertext);
    // QString mekIVB64 = toBase64String(encrypted.iv);
    // QString mekTagB64 = toBase64String(encrypted.tag);
 
    // 6. Call AuthService to register user
    m_authDb->registerUser(username, authSaltB64, encSaltB64, authKeyB64, encryptedMEKB64/* authHashB64, mekIVB64, mekTagB64*/);
}

void LoginModel::changePassword(const QString& username,
                              const QString& oldPassword,
                              const QString& newPassword,
                              const QString& confirmPassword) {
    if (newPassword != confirmPassword) {
        emit authError("New passwords don't match");
        return;
    }
    
    emit authError("Change password not implemented with new crypto flow");
}