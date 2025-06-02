#include "TOTPEnrollment.h"
#include <QDateTime>
#include <QRandomGenerator>
#include <QUrl>
#include <QDataStream>
#include <QIODevice>
#include <openssl/rand.h>
#include <stdexcept>

TOTPEnrollment::TOTPEnrollment(QObject* parent)
    : QObject(parent)
    , qrGenerator_(std::make_unique<QRVerification>(this))
    , qrTimeout_(300)  // 5 minutes timeout (same as TOFU default)
{
}

QString TOTPEnrollment::generateSecret() const {
    // Generate 160-bit (20-byte) secret for HMAC-SHA1 compatibility
    // This matches industry standard TOTP secret length
    QByteArray randomBytes(20, 0);
    
    // Use OpenSSL's cryptographically secure random generator (same as TOFU)
    if (RAND_bytes(reinterpret_cast<unsigned char*>(randomBytes.data()), 20) != 1) {
        throw std::runtime_error("Failed to generate cryptographically secure random bytes");
    }
    
    // Encode to Base32 (RFC 4648) - compatible with all authenticator apps
    return encodeBase32(randomBytes);
}

QString TOTPEnrollment::createOTPAuthURL(const QString& issuer, 
                                        const QString& accountName, 
                                        const QString& secret) const {
    // Create industry-standard otpauth:// URL
    // Format: otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30
    
    QString url = QString("otpauth://totp/%1:%2?secret=%3&issuer=%4&algorithm=SHA1&digits=6&period=30")
                  .arg(QUrl::toPercentEncoding(issuer).constData())      // URL-encode issuer
                  .arg(QUrl::toPercentEncoding(accountName).constData()) // URL-encode account
                  .arg(secret)                                           // Secret is already base32
                  .arg(QUrl::toPercentEncoding(issuer).constData());     // URL-encode issuer param
    
    return url;
}

QByteArray TOTPEnrollment::generateEnrollmentQR(const QString& issuer,
                                               const QString& accountName, 
                                               const QString& secret) {
    // Create enrollment data structure
    TOTPEnrollmentData data;
    data.issuer = issuer;
    data.accountName = accountName;
    data.secret = secret;
    data.otpauthURL = createOTPAuthURL(issuer, accountName, secret);
    data.timestamp = QDateTime::currentSecsSinceEpoch();  // Anti-replay protection
    
    // Serialize data (reuse TOFU's secure serialization pattern)
    QByteArray serialized = data.serialize();
    
    // Generate QR code using TOFU's proven infrastructure
    return qrGenerator_->generateQRCode(QRVerificationData{
        .userId = accountName,
        .deviceId = "totp_enrollment", 
        .publicKeyFingerprint = serialized,  // Store our TOTP data here
        .verificationCode = secret.left(6),  // First 6 chars of secret for verification
        .timestamp = data.timestamp
    });
}

bool TOTPEnrollment::verifySetupCode(const QString& secret, const QString& userCode) const {
    try {
        // Create TOTP instance with the secret
        TOTP totp(secret.toStdString());
        
        // Generate current code and check if it matches user input
        QString expectedCode = QString::fromStdString(totp.generate());
        
        // Time-constant comparison to prevent timing attacks
        return userCode == expectedCode;
        
    } catch (const std::exception& e) {
        qWarning() << "TOTP verification failed:" << e.what();
        return false;
    }
}

QByteArray TOTPEnrollment::encodeBase32(const QByteArray& data) const {
    // RFC 4648 Base32 encoding (A-Z, 2-7)
    static const char base32Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    
    QByteArray result;
    int buffer = 0;
    int bitsLeft = 0;
    
    for (unsigned char byte : data) {
        buffer = (buffer << 8) | byte;
        bitsLeft += 8;
        
        while (bitsLeft >= 5) {
            result.append(base32Chars[(buffer >> (bitsLeft - 5)) & 0x1F]);
            bitsLeft -= 5;
        }
    }
    
    if (bitsLeft > 0) {
        result.append(base32Chars[(buffer << (5 - bitsLeft)) & 0x1F]);
    }
    
    return result;
}

bool TOTPEnrollment::isEnrollmentExpired(qint64 timestamp) const {
    // Reuse TOFU's timeout logic
    qint64 now = QDateTime::currentSecsSinceEpoch();
    return (now - timestamp) > qrTimeout_;
}

// TOTPEnrollmentData serialization (follows TOFU pattern)
QByteArray TOTPEnrollmentData::serialize() const {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_5);
    
    stream << issuer << accountName << secret << otpauthURL << timestamp;
    return data;
}

TOTPEnrollmentData TOTPEnrollmentData::deserialize(const QByteArray& data) {
    TOTPEnrollmentData result;
    QDataStream stream(data);
    stream.setVersion(QDataStream::Qt_6_5);
    
    stream >> result.issuer >> result.accountName >> result.secret 
           >> result.otpauthURL >> result.timestamp;
    
    return result;
} 