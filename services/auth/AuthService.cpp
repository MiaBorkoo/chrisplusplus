#include "AuthService.h"
#include "otp/TOTP.h"          
#include "otp/TOTPEnrollment.h"  // NEW
#include <QJsonObject>
#include <QSettings>           
#include <QDebug>


/**
 * @class AuthService
 * @brief Handles authentication operations.
 * @author jjola00
 *
 * This class handles authentication operations.
 */

AuthService::AuthService(Client* client, QObject* parent)
    : IAuthService(parent)
    , m_client(client)
    , m_settings(new QSettings(this))
    , m_totpEnrollment(std::make_unique<TOTPEnrollment>(this))  // NEW: Initialize enrollment
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

void AuthService::startTOTPEnrollment(const QString& username) {
    try {
        // Check if TOTP is already enabled
        if (hasTOTPEnabled()) {
            emit totpEnrollmentFailed("TOTP is already enabled for this account");
            return;
        }
        
        // Generate cryptographically secure secret
        m_pendingTOTPSecret = m_totpEnrollment->generateSecret();
        m_pendingUsername = username;
        
        // Create enrollment data
        TOTPEnrollmentData enrollmentData = m_totpEnrollment->createEnrollmentData(
            "MyShare",              // Issuer name
            username,               // Account name  
            m_pendingTOTPSecret     // Base32 secret
        );
        
        if (!enrollmentData.isValid()) {
            emit totpEnrollmentFailed("Failed to create enrollment data");
            return;
        }
        
        // Generate QR code
        QByteArray qrCode = m_totpEnrollment->generateEnrollmentQR(enrollmentData);
        
        if (qrCode.isEmpty()) {
            emit totpEnrollmentFailed("Failed to generate QR code");
            return;
        }
        
        // Emit signal with QR code and secret (for manual entry option)
        emit totpEnrollmentStarted(qrCode, m_pendingTOTPSecret);
        
        qDebug() << "TOTP enrollment started for user:" << username;
        
    } catch (const std::exception& e) {
        emit totpEnrollmentFailed(QString("Enrollment failed: %1").arg(e.what()));
    }
}

void AuthService::completeTOTPEnrollment(const QString& userCode) {
    if (m_pendingTOTPSecret.isEmpty()) {
        emit totpEnrollmentFailed("No enrollment in progress");
        return;
    }
    
    try {
        // Verify the user-entered code against the pending secret
        bool isValid = m_totpEnrollment->verifySetupCode(m_pendingTOTPSecret, userCode);
        
        if (isValid) {
            // Save secret to secure storage only after successful verification
            m_settings->setValue("totp/secret", m_pendingTOTPSecret);
            m_settings->setValue("totp/username", m_pendingUsername);
            m_settings->setValue("totp/enabled_at", QDateTime::currentDateTimeUtc());
            m_settings->sync();  // Force write to disk
            
            // Clear temporary data
            m_pendingTOTPSecret.clear();
            m_pendingUsername.clear();
            
            emit totpEnrollmentCompleted(true);
            emit totpStatusChanged(true);  // Notify that TOTP is now enabled
            
            qDebug() << "TOTP enrollment completed successfully";
            
        } else {
            emit totpEnrollmentCompleted(false);
            qDebug() << "TOTP enrollment failed: Invalid verification code";
        }
        
    } catch (const std::exception& e) {
        emit totpEnrollmentFailed(QString("Verification failed: %1").arg(e.what()));
    }
}

void AuthService::cancelTOTPEnrollment() {
    if (!m_pendingTOTPSecret.isEmpty()) {
        m_pendingTOTPSecret.clear();
        m_pendingUsername.clear();
        qDebug() << "TOTP enrollment cancelled";
    }
}

bool AuthService::hasTOTPEnabled() const {
    return !m_settings->value("totp/secret").toString().isEmpty();
}

void AuthService::disableTOTP() {
    m_settings->remove("totp/secret");
    m_settings->remove("totp/username");  
    m_settings->remove("totp/enabled_at");
    m_settings->sync();
    
    emit totpStatusChanged(false);
    qDebug() << "TOTP disabled";
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
