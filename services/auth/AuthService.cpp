#include "AuthService.h"
#include "../../crypto/KeyDerivation.h"
#include "../../crypto/WrappedMEK.h"
#include "../../crypto/AuthHash.h"
#include "otp/TOTP.h"          
#include <QJsonObject>
#include <QSettings>           

namespace {
    template <size_t N>
    QString toBase64String(const std::array<uint8_t, N>& data) {
        return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
    }

    QString toBase64String(const std::vector<uint8_t>& data) {
        return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
    }
}

AuthService::AuthService(std::shared_ptr<Client> client, QObject* parent)
    : ApiService(parent), m_client(client), m_settings(new QSettings(this))  
{
    if (m_client) {
        connect(m_client.get(), SIGNAL(responseReceived(int, QJsonObject)), 
                this, SLOT(handleResponseReceived(int, QJsonObject)));

        connect(m_client.get(), SIGNAL(networkError(QString)),
                this, SLOT(handleNetworkError(QString)));
    }
}


void AuthService::login(const QString& username, const QString& password) {
    // Validate inputs
    QString errorMessage;
    if (!m_validationService->validateUsername(username, errorMessage)) {
        emit errorOccurred(errorMessage);
        return;
    }
    if (!m_validationService->validatePassword(password, errorMessage)) {
        emit errorOccurred(errorMessage);
        return;
    }

    try {
        // TODO: Get salts from server first
        std::vector<uint8_t> authSalt1; // = getSaltsFromServer(username).authSalt1;
        std::vector<uint8_t> authSalt2; // = getSaltsFromServer(username).authSalt2;
        std::vector<uint8_t> encSalt;   // = getSaltsFromServer(username).encSalt;

        // Derive keys and compute auth hash
        KeyDerivation kd;
        DerivedKeys keys = kd.deriveKeysFromPassword(password.toStdString(), authSalt1, encSalt);
        std::vector<uint8_t> serverAuthKeyVec(keys.serverAuthKey.begin(), keys.serverAuthKey.end());
        std::vector<uint8_t> authHash = AuthHash::computeAuthHash(serverAuthKeyVec, authSalt2);

        // Convert to base64 and send to server
        QString authHashB64 = toBase64String(authHash);
        hashedLogin(username, authHashB64);
    } catch (const std::exception& e) {
        emit errorOccurred(QString("Login failed: %1").arg(e.what()));
    }
}

void AuthService::hashedLogin(const QString& username, const QString& authHash) {
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

void AuthService::registerUser(const QString& username, const QString& password, const QString& confirmPassword) {
    // Validate inputs
    QString errorMessage;
    if (!m_validationService->validateUsername(username, errorMessage)) {
        emit errorOccurred(errorMessage);
        return;
    }
    if (!m_validationService->validatePassword(password, errorMessage)) {
        emit errorOccurred(errorMessage);
        return;
    }
    if (!m_validationService->validatePasswordMatch(password, confirmPassword, errorMessage)) {
        emit errorOccurred(errorMessage);
        return;
    }

    try {
        // 1. Generate salts
        std::vector<uint8_t> authSalt1 = generateSalt();
        std::vector<uint8_t> encSalt = generateSalt();

        // 2. Derive keys from password and salts
        KeyDerivation kd;
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

        // 6. Convert all binary data to Base64
        QString authHashB64 = toBase64String(authHash);
        QString authSalt1B64 = toBase64String(authSalt1);
        QString authSalt2B64 = toBase64String(authSalt2);
        QString encSaltB64 = toBase64String(encSalt);
        QString encryptedMEKB64 = toBase64String(encrypted.ciphertext);
        QString mekIVB64 = toBase64String(encrypted.iv);
        QString mekTagB64 = toBase64String(encrypted.tag);

        // 7. Call the low-level registration method
        registerUser(username, authHashB64, encryptedMEKB64, 
                    authSalt1B64, authSalt2B64, encSaltB64,
                    mekIVB64, mekTagB64);
    } catch (const std::exception& e) {
        emit errorOccurred(QString("Registration failed: %1").arg(e.what()));
    }
}

// Low-level registration
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
                               const QString& oldPassword,
                               const QString& newPassword) {
    // Validate inputs
    QString errorMessage;
    if (!m_validationService->validatePassword(newPassword, errorMessage)) {
        emit errorOccurred(errorMessage);
        return;
    }

    try {
        // TODO: Get current salts from server
        std::vector<uint8_t> oldAuthSalt1; // = getCurrentSalts().authSalt1;
        std::vector<uint8_t> oldAuthSalt2; // = getCurrentSalts().authSalt2;
        std::vector<uint8_t> oldEncSalt;   // = getCurrentSalts().encSalt;

        // Generate new salts
        std::vector<uint8_t> newAuthSalt1 = generateSalt();
        std::vector<uint8_t> newAuthSalt2 = generateSalt();
        std::vector<uint8_t> newEncSalt = generateSalt();

        // Derive keys and compute auth hashes
        KeyDerivation kd;
        DerivedKeys oldKeys = kd.deriveKeysFromPassword(oldPassword.toStdString(), oldAuthSalt1, oldEncSalt);
        DerivedKeys newKeys = kd.deriveKeysFromPassword(newPassword.toStdString(), newAuthSalt1, newEncSalt);

        std::vector<uint8_t> oldServerAuthKeyVec(oldKeys.serverAuthKey.begin(), oldKeys.serverAuthKey.end());
        std::vector<uint8_t> newServerAuthKeyVec(newKeys.serverAuthKey.begin(), newKeys.serverAuthKey.end());

        std::vector<uint8_t> oldAuthHash = AuthHash::computeAuthHash(oldServerAuthKeyVec, oldAuthSalt2);
        std::vector<uint8_t> newAuthHash = AuthHash::computeAuthHash(newServerAuthKeyVec, newAuthSalt2);

        // TODO: Get current MEK and re-encrypt it with new key
        std::vector<unsigned char> mek; // = getCurrentMEK();
        std::vector<uint8_t> newMekWrapperKey(newKeys.mekWrapperKey.begin(), newKeys.mekWrapperKey.end());
        EncryptedMEK newEncryptedMEK = encryptMEKWithWrapperKey(mek, newMekWrapperKey);

        // Convert to base64
        QString oldAuthHashB64 = toBase64String(oldAuthHash);
        QString newAuthHashB64 = toBase64String(newAuthHash);
        QString newEncryptedMEKB64 = toBase64String(newEncryptedMEK.ciphertext);

        changePassword(username, oldAuthHashB64, newAuthHashB64, newEncryptedMEKB64);
    } catch (const std::exception& e) {
        emit errorOccurred(QString("Password change failed: %1").arg(e.what()));
    }
}

// Low-level password change
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

std::vector<uint8_t> AuthService::generateSalt() const {
    KeyDerivation kd;
    return kd.generateSalt();
}

std::vector<unsigned char> AuthService::generateMEK() const {
    return generateMEK();
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