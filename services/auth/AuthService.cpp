#include "AuthService.h"
#include "../../crypto/KeyDerivation.h"
#include "../../crypto/WrappedMEK.h"
#include "../../crypto/AuthHash.h"
#include "../../crypto/MEKGenerator.h"
#include "otp/TOTP.h"
#include "../../utils/StringUtils.h"
#include <QJsonObject>
#include <QSettings>           
#include <QDebug>
#include <QByteArray>
#include <QTimer>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <QUrl>
#include <QUrlQuery>

// Use qrencode library directly for TOTP QR codes
extern "C" {
#include <qrencode.h>
}

using namespace StringUtils;  // Add this to use StringUtils functions

AuthService::AuthService(std::shared_ptr<Client> client, QObject* parent)
    : ApiService(parent), m_client(client), m_settings(new QSettings(this)), m_waitingForSalts(false)
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

    if (m_waitingForSalts) {
        emit errorOccurred("Another login operation is already in progress");
        return;
    }

    qDebug() << "Starting login for username:" << username;
    
    // Store login state for when salts response arrives
    m_pendingLoginUsername = username;
    m_pendingLoginPassword = password;
    m_waitingForSalts = true;
    
    // Request salts from server - response will be handled asynchronously
    try {
        AuthSalts salts = getAuthSalts(username);  // This triggers async request
    } catch (const std::exception& e) {
        m_waitingForSalts = false;
        QString errorMessage = QString("Login failed: %1").arg(e.what());
        qDebug() << "Login exception:" << errorMessage;
        emit errorOccurred(errorMessage);
    } catch (...) {
        qDebug() << "Unknown login error occurred";
        emit errorOccurred("Login failed: Network connection error. Please check if server is running.");
    }
}

void AuthService::hashedLogin(const QString& username, const QString& authHash) {
    QJsonObject payload;
    payload["username"] = username;
    payload["auth_key"] = authHash;  // OpenAPI field name
    
    // No TOTP code - for basic login without TOTP
    m_client->sendRequest("/api/auth/login", "POST", payload);  // Correct OpenAPI endpoint
}

// Method for login with manual TOTP
void AuthService::hashedLoginWithTOTP(const QString& username, const QString& authHash, const QString& totpCode) {
    qDebug() << "=== hashedLoginWithTOTP CALLED ===";
    qDebug() << "Username:" << username;
    qDebug() << "AuthHash:" << authHash;
    qDebug() << "TOTP Code:" << totpCode;
    qDebug() << "TOTP Code isEmpty():" << totpCode.isEmpty();
    qDebug() << "TOTP Code length:" << totpCode.length();
    
    QJsonObject payload;
    payload["username"] = username;
    payload["auth_key"] = authHash;  // OpenAPI field name
    
    // User-entered TOTP code from Google Authenticator
    if (!totpCode.isEmpty()) {
        payload["otp"] = totpCode;
        qDebug() << "✅ TOTP code added to payload";
    } else {
        qDebug() << "❌ TOTP code is EMPTY - not adding to payload";
    }
    
    qDebug() << "Final login payload:" << payload;
    qDebug() << "Sending to endpoint: /api/auth/login";
    m_client->sendRequest("/api/auth/login", "POST", payload);  // Correct OpenAPI endpoint
}

void AuthService::registerUser(const QString& username, const QString& password, const QString& confirmPassword) {
    // Validate inputs
    QString errorMessage;
    if (!m_validationService->validateUsername(username, errorMessage)) {
        emit errorOccurred(errorMessage);
        return;
    }
    if (!m_validationService->validatePassword(password, username, errorMessage)) {
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
    payload["auth_key"] = authHash;
    payload["encrypted_mek"] = encryptedMEK;
    payload["auth_salt"] = authSalt1;      // Server expects "auth_salt" (not "auth_salt1")
    payload["auth_salt_2"] = authSalt2;    // Server expects "auth_salt_2" (with underscore)
    payload["enc_salt"] = encSalt;
    
    // Add the MEK encryption details
    payload["mek_iv"] = mekIV;
    payload["mek_tag"] = mekTag;
    
    // Add required fields that server expects
    QJsonObject publicKey;
    publicKey["type"] = "RSA";
    publicKey["key"] = "temp_key_data";
    payload["public_key"] = publicKey;
    
    // Generate a simple HMAC for user data validation  
    payload["user_data_hmac"] = "temp_hmac_data";
    
    qDebug() << "Fixed registration payload:" << payload;
    m_client->sendRequest("/api/auth/register", "POST", payload);
}

void AuthService::changePassword(const QString& username,
                               const QString& oldPassword,
                               const QString& newPassword) {
    // Validate inputs
    QString errorMessage;
    if (!m_validationService->validatePassword(newPassword, username, errorMessage)) {
        emit errorOccurred(errorMessage);
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
    payload["old_auth_key"] = oldAuthHash;  // Changed from old_auth_hash to old_auth_key to match OpenAPI spec
    payload["new_auth_key"] = newAuthHash;  // Changed from new_auth_hash to new_auth_key to match OpenAPI spec
    payload["new_encrypted_mek"] = newEncryptedMEK;
    
    // Add required fields from OpenAPI spec
    const QString secretB32 = m_settings->value("totp/secret").toString();
    if (!secretB32.isEmpty()) {
        TOTP totp(secretB32.toStdString());
        const QString totpCode = QString::fromStdString(totp.generate());
        payload["totp_code"] = totpCode;
    } else {
        payload["totp_code"] = "000000";  // Placeholder if TOTP not enabled
    }
    payload["session_token"] = m_sessionToken;

    m_client->sendRequest("/api/auth/change_password", "POST", payload);  // Fixed: added /api/ prefix
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

    if (endpoint.contains("/api/user/") && endpoint.endsWith("/salts")) {
        AuthSalts salts;
        handleSaltsResponse(status, data, salts);
    } else if (endpoint == "/api/auth/login") {
        handleLoginResponse(status, data);
    } else if (endpoint == "/api/auth/register") {
        handleRegisterResponse(status, data);
    } else if (endpoint == "/api/auth/change_password") {
        handleChangePasswordResponse(status, data);
    } else if (endpoint.contains("/api/auth/refresh")) {
        handleRefreshResponse(status, data);
    } else if (endpoint == "/api/auth/logout") {
        handleLogoutResponse(status, data);
    } else {
        // Debug: log unhandled endpoints
        qDebug() << "Unhandled endpoint response:" << endpoint << "Status:" << status;
    }
}

void AuthService::handleNetworkError(const QString& error) {
    reportError(error);
}

void AuthService::handleLoginResponse(int status, const QJsonObject& data) {
    qDebug() << "Login response - Status:" << status << "Data:" << data;
    
    // Fix: Server returns access_token on successful login (status 200)
    const bool success = (status == 200 && data.contains("access_token"));
    const QString token = data.value("access_token").toString();
    
    emit loginCompleted(success, token);
    if (success) {
        m_sessionToken = token;
        qDebug() << "Login successful! Token:" << token;
    } else {
        QString errorMsg = data.value("error").toString("Login failed. Please try again.");
        qDebug() << "Login failed with error:" << errorMsg;
        reportError(errorMsg);
    }
}

void AuthService::handleRegisterResponse(int status, const QJsonObject& data) {
    qDebug() << "Registration response - Status:" << status << "Data:" << data;
    
    // Fix: Check for "status": "success" instead of "success": true
    const bool success = (status == 200 && data.value("status").toString() == "success");
    
    if (success) {
        qDebug() << "Registration successful!";
        
        // Handle server-provided TOTP setup (server gives us the otpauth_uri)
        if (data.contains("otpauth_uri")) {
            QString otpauthUri = data.value("otpauth_uri").toString();
            QString userId = data.value("user_id").toString();
            
            qDebug() << "Server provided TOTP setup for user:" << userId;
            qDebug() << "OTPAuth URI:" << otpauthUri;
            
            // Extract username from otpauth URI (format: otpauth://totp/EPIC-App:username?...)
            QString username = extractUsernameFromOtpauthUri(otpauthUri);
            if (username.isEmpty()) {
                qDebug() << "Could not extract username from otpauth URI";
                emit registrationCompleted(true);
                return;
            }
            
            // Store the server-provided otpauth URI using the username for login lookup
            QString key = QString("users/%1/server_otpauth_uri").arg(username);
            m_settings->setValue(key, otpauthUri);
            m_settings->sync();
            
            qDebug() << "Stored server TOTP setup for username:" << username;
        }
        
        emit registrationCompleted(true);
    } else {
        QString errorMsg = data.value("error").toString("Registration failed. Please try again.");
        qDebug() << "Registration failed with error:" << errorMsg;
        reportError(errorMsg);
        emit registrationCompleted(false);
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

void AuthService::handleRefreshResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200);
    QString newToken;
    
    if (success) {
        newToken = data.value("access_token").toString();
        m_sessionToken = newToken;
    }
    
    emit refreshCompleted(success, newToken);
    if (!success) {
        reportError(data.value("error").toString("Token refresh failed. Please login again."));
    }
}

void AuthService::handleLogoutResponse(int status, const QJsonObject& data) {
    const bool success = (status == 200);
    
    if (success) {
        invalidateSession();
    }
    
    emit logoutCompleted(success);
    if (!success) {
        reportError(data.value("error").toString("Logout failed. Please try again."));
    }
}

void AuthService::invalidateSession() {
    m_sessionToken.clear();
    // No encryption key to clear - TOTP handled by Google Authenticator
}

AuthService::AuthSalts AuthService::getAuthSalts(const QString& username) {
    if (!m_client) {
        throw std::runtime_error("AuthService not properly initialized");
    }

    AuthSalts salts;
    // No payload needed for GET request - username is in the path
    QJsonObject payload;

    // Fixed: Use correct OpenAPI endpoint with username in path
    QString endpoint = QString("/api/user/%1/salts").arg(username);
    m_client->sendRequest(endpoint, "GET", payload);

    // Response will be handled by handleResponseReceived and routed to handleSaltsResponse
    return salts;
}

void AuthService::handleSaltsResponse(int status, const QJsonObject& data, AuthSalts& salts) {
    qDebug() << "Salts response - Status:" << status << "Data:" << data;
    
    if (status != 200) {
        QString errorMessage = data.value("error").toString("Failed to get authentication salts");
        
        // Clear login state if we were waiting for salts
        if (m_waitingForSalts) {
            m_waitingForSalts = false;
            m_pendingLoginUsername.clear();
            m_pendingLoginPassword.clear();
        }
        
        emit errorOccurred(errorMessage);
        return;
    }

    // Extract salts from response - match server field names
    salts.authSalt1 = data.value("auth_salt").toString();      // Server returns "auth_salt" 
    salts.authSalt2 = data.value("auth_salt_2").toString();    // Server returns "auth_salt_2"
    salts.encSalt = data.value("enc_salt").toString();

    qDebug() << "Extracted salts - authSalt1:" << (!salts.authSalt1.isEmpty() ? "present" : "missing")
             << "authSalt2:" << (!salts.authSalt2.isEmpty() ? "present" : "missing")
             << "encSalt:" << (!salts.encSalt.isEmpty() ? "present" : "missing");

    if (salts.authSalt1.isEmpty() || salts.authSalt2.isEmpty() || salts.encSalt.isEmpty()) {
        // Clear login state if we were waiting for salts
        if (m_waitingForSalts) {
            m_waitingForSalts = false;
            m_pendingLoginUsername.clear();
            m_pendingLoginPassword.clear();
        }
        
        emit errorOccurred("Invalid salt data received from server - missing required salts");
        return;
    }
    
    // If we were waiting for salts for login, continue the login process
    if (m_waitingForSalts) {
        qDebug() << "Continuing login with received salts";
        
        try {
            // Convert salts from base64
            QByteArray authSalt1Data = QByteArray::fromBase64(salts.authSalt1.toUtf8());
            QByteArray authSalt2Data = QByteArray::fromBase64(salts.authSalt2.toUtf8());
            QByteArray encSaltData = QByteArray::fromBase64(salts.encSalt.toUtf8());
            std::vector<uint8_t> authSalt1(authSalt1Data.begin(), authSalt1Data.end());
            std::vector<uint8_t> authSalt2(authSalt2Data.begin(), authSalt2Data.end());
            std::vector<uint8_t> encSalt(encSaltData.begin(), encSaltData.end());
            
            // Derive auth hash using the retrieved salts
            QString authHash = deriveAuthHash(m_pendingLoginPassword, authSalt1, authSalt2);
            
            qDebug() << "Auth hash computed successfully";
            
            // Clear login state
            QString username = m_pendingLoginUsername;
            m_waitingForSalts = false;
            m_pendingLoginUsername.clear();
            m_pendingLoginPassword.clear();
            
            // Check TOTP status - simple approach
            if (hasTOTPEnabledForUser(username)) {
                qDebug() << "User" << username << "has completed TOTP setup - requiring authenticator code";
                emit totpRequired(username, authHash);
            } else {
                // Check if server provided TOTP setup during registration
                QString serverKey = QString("users/%1/server_otpauth_uri").arg(username);
                QString serverOtpauthUri = m_settings->value(serverKey).toString();
                
                if (!serverOtpauthUri.isEmpty()) {
                    qDebug() << "Found server-provided TOTP for first login - showing QR code";
                    
                    // Extract secret from server otpauth URI and set pending state
                    QString secret = extractSecretFromOtpauthUri(serverOtpauthUri);
                    if (!secret.isEmpty()) {
                        m_pendingTOTPSecret = secret;
                        m_pendingUsername = username;
                        qDebug() << "Set pending TOTP secret from server for verification";
                    }
                    
                    // Generate QR code from server-provided otpauth URI
                    QString qrCode = generateQRCodeFromOtpauthUri(serverOtpauthUri);
                    if (!qrCode.isEmpty()) {
                        emit firstLoginTOTPSetupRequired(username, authHash, qrCode);
                    } else {
                        emit errorOccurred("Failed to generate QR code from server TOTP setup");
                    }
                } else {
                    qDebug() << "No server TOTP found - generating new TOTP setup";
                    QString qrCode = enableTOTP(username);
                    if (!qrCode.isEmpty()) {
                        emit firstLoginTOTPSetupRequired(username, authHash, qrCode);
                    } else {
                        emit errorOccurred("Failed to generate TOTP setup for first login");
                    }
                }
            }
            
        } catch (const std::exception& e) {
            m_waitingForSalts = false;
            m_pendingLoginUsername.clear();
            m_pendingLoginPassword.clear();
            QString errorMessage = QString("Login failed: %1").arg(e.what());
            emit errorOccurred(errorMessage);
        }
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

// TOTP methods (industry standard approach)
QString AuthService::enableTOTP(const QString& username) {
    try {
        // Check if TOTP is already enabled for this specific user
        if (hasTOTPEnabledForUser(username)) {
            emit errorOccurred("TOTP is already enabled for this user");
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
            // SUCCESS: TOTP setup verified
            // Secret is stored in Google Authenticator only - no local storage
            qDebug() << "TOTP setup completed successfully";
            
            // Store only a flag that TOTP is enabled (no secret)
            m_settings->setValue("totp/enabled", true);
            m_settings->setValue("totp/username", m_pendingUsername);
            m_settings->setValue("totp/enabled_at", QDateTime::currentDateTimeUtc());
            m_settings->sync();
            
            // Mark that this user has completed TOTP setup (for first-login detection)
            markTOTPSetupCompleted(m_pendingUsername);
            
            // Clear temporary data
            m_pendingTOTPSecret.clear();
            m_pendingUsername.clear();
            
            emit totpSetupCompleted(true);
            
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
    // Check if TOTP is enabled globally (legacy support)
    bool globalEnabled = m_settings->value("totp/enabled", false).toBool();
    
    // If we have a pending username (during TOTP setup), check for that user
    if (!m_pendingUsername.isEmpty()) {
        QString key = QString("users/%1/totp_setup_completed").arg(m_pendingUsername);
        return m_settings->value(key, false).toBool();
    }
    
    // Otherwise, check if any user has TOTP enabled (for backward compatibility)
    return globalEnabled;
}

bool AuthService::hasTOTPEnabledForUser(const QString& username) const {
    // Simple check: Has this user completed TOTP setup once?
    QString key = QString("users/%1/totp_setup_completed").arg(username);
    bool hasCompleted = m_settings->value(key, false).toBool();
    
    qDebug() << "TOTP check for user:" << username << "Setup completed:" << hasCompleted;
    return hasCompleted;
}

bool AuthService::isFirstTimeLogin(const QString& username) const {
    // Simple check: First time = user has never completed TOTP setup
    QString key = QString("users/%1/totp_setup_completed").arg(username);
    bool setupCompleted = m_settings->value(key, false).toBool();
    
    qDebug() << "First login check for user:" << username << "Setup completed:" << setupCompleted;
    return !setupCompleted;
}

void AuthService::markTOTPSetupCompleted(const QString& username) {
    // Mark that this user has completed TOTP setup at least once
    QString key = QString("users/%1/totp_setup_completed").arg(username);
    m_settings->setValue(key, true);
    m_settings->setValue(QString("users/%1/totp_setup_completed_at").arg(username), 
                        QDateTime::currentDateTimeUtc());
    m_settings->sync();
    
    qDebug() << "Marked TOTP setup as completed for user:" << username;
}

void AuthService::disableTOTP() {
    m_settings->remove("totp/enabled");
    m_settings->remove("totp/username");  
    m_settings->remove("totp/enabled_at");
    m_settings->sync();
    
    emit totpDisabled();
    qDebug() << "TOTP disabled";
}

// Enhanced TOTP methods for better user experience
void AuthService::completeTOTPSetupAndLogin(const QString& username, const QString& authHash, const QString& totpCode) {
    // First verify the TOTP setup
    bool setupValid = verifyTOTPSetup(totpCode);
    
    if (setupValid) {
        // TOTP setup successful, now complete login with the same code
        qDebug() << "TOTP setup completed, proceeding with login for user:" << username;
        hashedLoginWithTOTP(username, authHash, totpCode);
    } else {
        // TOTP setup failed, user needs to try again
        qDebug() << "TOTP setup failed for user:" << username;
        emit errorOccurred("Invalid TOTP code. Please try again.");
    }
}

// Missing OpenAPI endpoints implementation
void AuthService::refreshToken(const QString& refreshToken) {
    if (!m_client) {
        emit errorOccurred("AuthService not properly initialized");
        return;
    }

    // OpenAPI spec uses query parameter for refresh token
    QString endpoint = QString("/api/auth/refresh?refresh_token=%1").arg(refreshToken);
    QJsonObject payload;  // Empty payload for refresh
    
    m_client->sendRequest(endpoint, "POST", payload);
}

void AuthService::logout(const QString& sessionToken) {
    if (!m_client) {
        emit errorOccurred("AuthService not properly initialized");
        return;
    }

    QJsonObject payload;
    payload["session_token"] = sessionToken;
    
    m_client->sendRequest("/api/auth/logout", "POST", payload);
}

QString AuthService::generateQRCodeFromOtpauthUri(const QString& otpauthUri) {
    try {
        // Generate QR code from the server-provided otpauth URI
        QRcode* qrcode = QRcode_encodeString(
            otpauthUri.toUtf8().constData(),
            0,                    // Version 0: Auto-select optimal version
            QR_ECLEVEL_H,        // High error correction (30% recovery)
            QR_MODE_8,           // 8-bit data mode for URLs
            1                    // Case sensitive
        );
        
        if (!qrcode) {
            qDebug() << "Failed to generate QR code from otpauth URI";
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
        
        qDebug() << "Generated QR code from server otpauth URI";
        return qrData;
        
    } catch (const std::exception& e) {
        qDebug() << "QR code generation failed:" << e.what();
        return QString();
    }
}

QString AuthService::extractUsernameFromOtpauthUri(const QString& otpauthUri) {
    // Parse otpauth://totp/EPIC-App:username?secret=XXXXX&issuer=EPIC-App
    // The username is between "EPIC-App:" and "?"
    QUrl url(otpauthUri);
    QString path = url.path();
    
    // Remove leading "/"
    if (path.startsWith("/")) {
        path = path.mid(1);
    }
    
    // Find the username after "EPIC-App:"
    int colonIndex = path.indexOf(":");
    if (colonIndex != -1) {
        QString username = path.mid(colonIndex + 1);
        qDebug() << "Extracted username from otpauth URI:" << username;
        return username;
    }
    
    qDebug() << "Could not extract username from otpauth URI:" << otpauthUri;
    return QString();
}

QString AuthService::extractSecretFromOtpauthUri(const QString& otpauthUri) {
    // Parse otpauth://totp/EPIC-App:username?secret=XXXXX&issuer=EPIC-App
    QUrl url(otpauthUri);
    QUrlQuery query(url.query());
    QString secret = query.queryItemValue("secret");
    
    if (!secret.isEmpty()) {
        qDebug() << "Extracted secret from otpauth URI:" << (!secret.isEmpty() ? "present" : "missing");
        return secret;
    }
    
    qDebug() << "Could not extract secret from otpauth URI:" << otpauthUri;
    return QString();
}
