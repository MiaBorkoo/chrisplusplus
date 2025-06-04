#include "AuthService.h"
#include "../../crypto/KeyDerivation.h"
#include "../../crypto/WrappedMEK.h"
#include "../../crypto/AuthHash.h"
#include "../../crypto/MEKGenerator.h"
#include "otp/TOTP.h"
#include "../../tofu/QRVerification.h"          
#include <QJsonObject>
#include <QSettings>           
#include <QDebug>
#include <QByteArray>

// Use qrencode library directly for TOTP QR codes
extern "C" {
#include <qrencode.h>
}

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
    m_validationService = std::make_shared<ValidationService>();
    
    if (m_client) {
        connect(m_client.get(), SIGNAL(responseReceived(int, QJsonObject)), 
                this, SLOT(handleResponseReceived(int, QJsonObject)));

        connect(m_client.get(), SIGNAL(networkError(QString)),
                this, SLOT(handleNetworkError(QString)));
    }
}


void AuthService::login(const QString& username, const QString& password) {
    if (!m_client) {
        emit errorOccurred("AuthService not properly initialized");
        return;
    }

    try {
        // Get current salts from server
        AuthSalts salts = getAuthSalts(username);
        
        // Convert salts from base64
        QByteArray authSalt1Data = QByteArray::fromBase64(salts.authSalt1.toUtf8());
        QByteArray authSalt2Data = QByteArray::fromBase64(salts.authSalt2.toUtf8());
        QByteArray encSaltData = QByteArray::fromBase64(salts.encSalt.toUtf8());
        std::vector<uint8_t> authSalt1(authSalt1Data.begin(), authSalt1Data.end());
        std::vector<uint8_t> authSalt2(authSalt2Data.begin(), authSalt2Data.end());
        std::vector<uint8_t> encSalt(encSaltData.begin(), encSaltData.end());
        
        // Derive ALL keys including mekWrapperKey (needed for TOTP encryption)
        KeyDerivation kd;
        DerivedKeys keys = kd.deriveKeysFromPassword(password.toStdString(), authSalt1, encSalt);
        
        // Store mekWrapperKey for TOTP encryption/decryption
        m_mekWrapperKey = std::vector<uint8_t>(keys.mekWrapperKey.begin(), keys.mekWrapperKey.end());
        
        // Compute auth hash using server auth key and second salt
        std::vector<uint8_t> serverAuthKeyVec(keys.serverAuthKey.begin(), keys.serverAuthKey.end());
        std::vector<uint8_t> authHashVec = AuthHash::computeAuthHash(serverAuthKeyVec, authSalt2);
        QString authHash = toBase64String(authHashVec);
        
        // Proceed with hashed login
        hashedLogin(username, authHash);
        
    } catch (const std::exception& e) {
        QString errorMessage = QString("Login failed: %1").arg(e.what());
        emit errorOccurred(errorMessage);
    }
}

void AuthService::hashedLogin(const QString& username, const QString& authHash) {
    QJsonObject payload;
    payload["username"] = username;
    payload["auth_hash"] = authHash;
    
    // Check for encrypted TOTP secret
    const QString encryptedSecret = m_settings->value("totp/secret").toString();
    if (!encryptedSecret.isEmpty() && !m_mekWrapperKey.empty()) {
        try {
            // Decrypt TOTP secret using mekWrapperKey
            QString secretB32 = decryptTOTPSecret(encryptedSecret, m_mekWrapperKey);
            if (!secretB32.isEmpty()) {
                TOTP totp(secretB32.toStdString());  
                const QString otp = QString::fromStdString(totp.generate());  
                payload["otp"] = otp;
                qDebug() << "TOTP code generated for login";
            } else {
                qWarning() << "Failed to decrypt TOTP secret during login";
            }
        } catch (const std::exception& e) {
            qWarning() << "TOTP decryption error during login:" << e.what();
        }
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
        // Get current salts from server
        AuthSalts salts = getAuthSalts(username);
        
        // Convert salts from base64
        QByteArray authSalt1Data = QByteArray::fromBase64(salts.authSalt1.toUtf8());
        QByteArray authSalt2Data = QByteArray::fromBase64(salts.authSalt2.toUtf8());
        std::vector<uint8_t> authSalt1(authSalt1Data.begin(), authSalt1Data.end());
        std::vector<uint8_t> authSalt2(authSalt2Data.begin(), authSalt2Data.end());

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

std::vector<unsigned char> AuthService::createMEK() const {
    return generateMEK();
}

void AuthService::handleResponseReceived(int status, const QJsonObject& data) {
    // Get the endpoint from the response or context
    QString endpoint = data.value("endpoint").toString();

    if (endpoint == "/auth/salts") {
        AuthSalts salts;
        handleSaltsResponse(status, data, salts);
    } else if (endpoint == "/auth/login") {
        handleLoginResponse(status, data);
    } else if (endpoint == "/auth/register") {
        handleRegisterResponse(status, data);
    } else if (endpoint == "/auth/change-password") {
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
    // Clear encryption key for security
    m_mekWrapperKey.clear();
}

AuthService::AuthSalts AuthService::getAuthSalts(const QString& username) {
    if (!m_client) {
        throw std::runtime_error("AuthService not properly initialized");
    }

    AuthSalts salts;
    QJsonObject payload;
    payload["username"] = username;

    // Make synchronous request for salts
    m_client->sendRequest("/auth/salts", "GET", payload);

    // Response will be handled by handleResponseReceived and routed to handleSaltsResponse
    return salts;
}

void AuthService::handleSaltsResponse(int status, const QJsonObject& data, AuthSalts& salts) {
    if (status != 200) {
        QString errorMessage = data.value("error").toString("Failed to get authentication salts");
        emit errorOccurred(errorMessage);
        return;
    }

    // Extract salts from response
    salts.authSalt1 = data.value("auth_salt1").toString();
    salts.authSalt2 = data.value("auth_salt2").toString();
    salts.encSalt = data.value("enc_salt").toString();

    if (salts.authSalt1.isEmpty() || salts.authSalt2.isEmpty() || salts.encSalt.isEmpty()) {
        emit errorOccurred("Invalid salt data received from server");
        return;
    }
}

QString AuthService::deriveAuthHash(const QString& password,
                                  const std::vector<uint8_t>& authSalt1,
                                  const std::vector<uint8_t>& authSalt2) {
    // This method is now obsolete - key derivation is handled in login()
    // Keeping for backward compatibility, but should not be used
    try {
        // 1. Derive keys from password and first salt
        KeyDerivation kd;
        DerivedKeys keys = kd.deriveKeysFromPassword(password.toStdString(), authSalt1);

        // 2. Extract server auth key
        std::vector<uint8_t> serverAuthKeyVec(keys.serverAuthKey.begin(), keys.serverAuthKey.end());

        // 3. Compute auth hash using the server auth key and second salt
        std::vector<uint8_t> authHash = AuthHash::computeAuthHash(serverAuthKeyVec, authSalt2);

        // 4. Convert to base64 string
        return toBase64String(authHash);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Failed to derive auth hash: ") + e.what());
    }
}

// Simple TOTP methods (industry standard approach)
QString AuthService::enableTOTP(const QString& username) {
    try {
        // Check if TOTP is already enabled
        if (hasTOTPEnabled()) {
            emit errorOccurred("TOTP is already enabled for this account");
            return QString();
        }
        
        // Generate cryptographically secure secret using TOTP class
        m_pendingTOTPSecret = QString::fromStdString(TOTP::generateSecret());
        m_pendingUsername = username;
        
        // Create standard otpauth:// URL
        std::string otpauthURL = TOTP::createOTPAuthURL(
            "MyShare",                          // Issuer
            username.toStdString(),             // Account
            m_pendingTOTPSecret.toStdString()   // Secret
        );
        
        // Generate actual QR code image using qrencode
        QRcode* qrcode = QRcode_encodeString(
            otpauthURL.c_str(),
            0,                    // Version 0: Auto-select optimal version
            QR_ECLEVEL_H,        // High error correction (30% recovery)
            QR_MODE_8,           // 8-bit data mode for URLs
            1                    // Case sensitive
        );
        
        if (!qrcode) {
            emit errorOccurred("Failed to generate QR code");
            return QString();
        }
        
        // Convert QR matrix to image data
        int size = qrcode->width * qrcode->width;
        QByteArray qrImageData(reinterpret_cast<const char*>(qrcode->data), size);
        
        // Create metadata for QR reconstruction
        QByteArray metadata;
        QDataStream metaStream(&metadata, QIODevice::WriteOnly);
        metaStream << static_cast<qint32>(qrcode->width) << static_cast<qint32>(qrcode->version);
        
        QRcode_free(qrcode);
        
        // Combine metadata + image data and encode as base64
        QByteArray qrData = (metadata + qrImageData).toBase64();
        
        emit totpEnabled(qrData);
        qDebug() << "TOTP setup started for user:" << username;
        qDebug() << "OTP Auth URL:" << QString::fromStdString(otpauthURL);
        
        return qrData;  // Return actual QR code as base64
        
    } catch (const std::exception& e) {
        emit errorOccurred(QString("TOTP setup failed: %1").arg(e.what()));
        return QString();
    }
}

bool AuthService::verifyTOTPSetup(const QString& code) {
    if (m_pendingTOTPSecret.isEmpty()) {
        emit errorOccurred("No TOTP setup in progress");
        return false;
    }
    
    try {
        // Verify the user-entered code against the pending secret
        TOTP totp(m_pendingTOTPSecret.toStdString());
        bool isValid = totp.verify(code.toStdString());
        
        if (isValid) {
            // SECURITY: Store TOTP secret encrypted with user's mekWrapperKey
            if (!m_mekWrapperKey.empty()) {
                QString encryptedSecret = encryptTOTPSecret(m_pendingTOTPSecret, m_mekWrapperKey);
                if (!encryptedSecret.isEmpty()) {
                    m_settings->setValue("totp/secret", encryptedSecret);
                    m_settings->setValue("totp/username", m_pendingUsername);
                    m_settings->setValue("totp/enabled_at", QDateTime::currentDateTimeUtc());
                    m_settings->sync();
                    qDebug() << "TOTP secret encrypted and stored securely";
                } else {
                    emit errorOccurred("Failed to encrypt TOTP secret");
                    return false;
                }
            } else {
                emit errorOccurred("No encryption key available. Please log in first.");
                return false;
            }
            
            // Clear temporary data
            m_pendingTOTPSecret.clear();
            m_pendingUsername.clear();
            
            emit totpSetupCompleted(true);
            qDebug() << "TOTP setup completed successfully";
            
        } else {
            emit totpSetupCompleted(false);
            qDebug() << "TOTP setup failed: Invalid verification code";
        }
        
        return isValid;
        
    } catch (const std::exception& e) {
        emit errorOccurred(QString("TOTP verification failed: %1").arg(e.what()));
        return false;
    }
}

bool AuthService::hasTOTPEnabled() const {
    // Check if encrypted TOTP secret exists
    return !m_settings->value("totp/secret").toString().isEmpty();
}

void AuthService::disableTOTP() {
    m_settings->remove("totp/secret");
    m_settings->remove("totp/username");  
    m_settings->remove("totp/enabled_at");
    m_settings->sync();
    
    emit totpDisabled();
    qDebug() << "TOTP disabled";
}

// Secure TOTP storage implementation using existing crypto infrastructure
QString AuthService::encryptTOTPSecret(const QString& secret, const std::vector<uint8_t>& mekWrapperKey) {
    try {
        // Convert secret to bytes
        QByteArray secretBytes = secret.toUtf8();
        std::vector<uint8_t> secretVec(secretBytes.begin(), secretBytes.end());
        
        // Use existing WrappedMEK encryption (AES-256-GCM)
        EncryptedMEK encrypted = encryptMEKWithWrapperKey(secretVec, mekWrapperKey);
        
        // Serialize encrypted data for storage
        QByteArray serialized;
        QDataStream stream(&serialized, QIODevice::WriteOnly);
        stream.setVersion(QDataStream::Qt_6_5);
        
        // Store ciphertext, IV, and auth tag
        stream << QByteArray(reinterpret_cast<const char*>(encrypted.ciphertext.data()), encrypted.ciphertext.size());
        stream << QByteArray(reinterpret_cast<const char*>(encrypted.iv.data()), encrypted.iv.size());
        stream << QByteArray(reinterpret_cast<const char*>(encrypted.tag.data()), encrypted.tag.size());
        
        return serialized.toBase64();
        
    } catch (const std::exception& e) {
        qWarning() << "Failed to encrypt TOTP secret:" << e.what();
        return QString();
    }
}

QString AuthService::decryptTOTPSecret(const QString& encryptedSecret, const std::vector<uint8_t>& mekWrapperKey) {
    try {
        // Deserialize encrypted data
        QByteArray serialized = QByteArray::fromBase64(encryptedSecret.toUtf8());
        QDataStream stream(serialized);
        stream.setVersion(QDataStream::Qt_6_5);
        
        QByteArray ciphertext, iv, tag;
        stream >> ciphertext >> iv >> tag;
        
        // Create EncryptedMEK structure
        EncryptedMEK encrypted;
        encrypted.ciphertext = std::vector<uint8_t>(ciphertext.begin(), ciphertext.end());
        encrypted.iv = std::vector<uint8_t>(iv.begin(), iv.end());
        encrypted.tag = std::vector<uint8_t>(tag.begin(), tag.end());
        
        // Decrypt using existing infrastructure
        std::vector<uint8_t> decrypted = decryptMEKWithWrapperKey(encrypted, mekWrapperKey);
        
        // Convert back to QString
        QByteArray secretBytes(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        return QString::fromUtf8(secretBytes);
        
    } catch (const std::exception& e) {
        qWarning() << "Failed to decrypt TOTP secret:" << e.what();
        return QString();
    }
}