#include "SignUpModel.h"
#include "../crypto/KeyDerivation.h"
#include "../crypto/MEKGenerator.h"
#include "../crypto/WrappedMEK.h"
#include "../crypto/AuthHash.h"

/**
 * @class SignUpModel
 * @brief Manages user registration operations.
 * @author jjola00
 *
 * This class handles user registration operations.
 */

template <size_t N>
QString toBase64String(const std::array<uint8_t, N>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

QString toBase64String(const std::vector<uint8_t>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

SignUpModel::SignUpModel(IAuthService* authDb, QObject* parent)
    : QObject(parent), m_authDb(authDb) 
{
    connect(m_authDb, &IAuthService::registrationCompleted,
            this, &SignUpModel::handleRegistrationCompleted);
}

void SignUpModel::handleRegistrationCompleted(bool success) {
    if (success) {
        emit registrationSuccess();
    } else {
        emit registrationError("Registration failed");
    }
}

void SignUpModel::registerUser(const QString& username, 
                             const QString& password,
                             const QString& confirmPassword) {
    if (username.isEmpty() || password.isEmpty()) {
        emit registrationError("Fields cannot be empty");
        return;
    }
    if (password != confirmPassword) {
        emit registrationError("Passwords don't match");
        return;
    }

    try {
        // 1. Generate salts
        KeyDerivation kd;
        std::vector<uint8_t> authSalt1 = kd.generateSalt();
        std::vector<uint8_t> encSalt = kd.generateSalt();

        // 2. Derive keys from password and salts
        DerivedKeys keys = kd.deriveKeysFromPassword(password.toStdString(), authSalt1, encSalt);

        // 3. Generate second auth salt and compute auth hash
        std::vector<uint8_t> authSalt2 = AuthHash::generateSalt();
        std::vector<uint8_t> serverAuthKeyVec(keys.serverAuthKey.begin(), keys.serverAuthKey.end());
        std::vector<uint8_t> authHash = AuthHash::computeAuthHash(serverAuthKeyVec, authSalt2);

        // 4. Generate a random MEK
        std::vector<unsigned char> mek = generateMEK();

        // 5. Encrypt the MEK with the MEK Wrapper Key
        std::vector<uint8_t> mekWrapperKey(keys.mekWrapperKey.begin(), keys.mekWrapperKey.end());
        EncryptedMEK encrypted = encryptMEKWithWrapperKey(mek, mekWrapperKey);

        // 6. Prepare data to send to server (Base64 encode all binary fields)
        QString authSalt1B64 = toBase64String(authSalt1);
        QString authSalt2B64 = toBase64String(authSalt2);
        QString encSaltB64 = toBase64String(encSalt);
        QString authHashB64 = toBase64String(authHash);
        QString encryptedMEKB64 = toBase64String(encrypted.ciphertext);
        QString mekIVB64 = toBase64String(encrypted.iv);
        QString mekTagB64 = toBase64String(encrypted.tag);
    
        // 7. Call AuthService to register user with all required parameters
        m_authDb->registerUser(username, 
                             authHashB64,
                             encryptedMEKB64,
                             authSalt1B64,
                             authSalt2B64,
                             encSaltB64,
                             mekIVB64,
                             mekTagB64);
    } catch (const std::exception& e) {
        emit registrationError(QString("Registration failed: %1").arg(e.what()));
    }
} 