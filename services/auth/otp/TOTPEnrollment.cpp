#include "TOTPEnrollment.h"
#include <QDateTime>
#include <QRandomGenerator>
#include <QUrl>
#include <QDataStream>
#include <QIODevice>
#include <QDebug>
#include <openssl/rand.h>
#include <stdexcept>

// Using qrencode library for QR code generation (same as TOFU)
extern "C" {
#include <qrencode.h>
}

// ============================================================================
// TOTPEnrollmentData Implementation
// ============================================================================

QByteArray TOTPEnrollmentData::serialize() const {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_5);
    
    stream << issuer << accountName << secret << otpauthURL 
           << timestamp << verificationCode;
    return data;
}

TOTPEnrollmentData TOTPEnrollmentData::deserialize(const QByteArray& data) {
    TOTPEnrollmentData result;
    QDataStream stream(data);
    stream.setVersion(QDataStream::Qt_6_5);
    
    stream >> result.issuer >> result.accountName >> result.secret 
           >> result.otpauthURL >> result.timestamp >> result.verificationCode;
    
    return result;
}

bool TOTPEnrollmentData::isValid() const {
    return !issuer.isEmpty() && 
           !accountName.isEmpty() && 
           !secret.isEmpty() && 
           !otpauthURL.isEmpty() &&
           !verificationCode.isEmpty() &&
           timestamp > 0;
}

bool TOTPEnrollmentData::isExpired(int timeoutSeconds) const {
    qint64 now = QDateTime::currentSecsSinceEpoch();
    return (now - timestamp) > timeoutSeconds;
}

// ============================================================================
// TOTPQRGenerator Implementation
// ============================================================================

TOTPQRGenerator::TOTPQRGenerator(QObject* parent)
    : QObject(parent)
    , errorCorrectionLevel_(QR_ECLEVEL_H)  // Highest error correction (30% recovery)
{
}

QByteArray TOTPQRGenerator::generateTOTPQRCode(const TOTPEnrollmentData& data) {
    if (!data.isValid()) {
        qWarning() << "TOTPQRGenerator: Invalid enrollment data";
        return QByteArray();
    }
    
    // For TOTP QR codes, we encode the otpauth:// URL directly
    // This is the industry standard approach that all authenticator apps expect
    QByteArray otpauthBytes = data.otpauthURL.toUtf8();
    
    // Generate QR code with high error correction
    QRcode* qrcode = QRcode_encodeString(
        otpauthBytes.constData(),
        0,  // Version 0: Auto-select optimal QR version
        static_cast<QRecLevel>(errorCorrectionLevel_),
        QR_MODE_8,  // QR_MODE_8 for binary data (otpauth:// URLs)
        1           // Case sensitive
    );
    
    if (!qrcode) {
        qWarning() << "TOTPQRGenerator: QR code generation failed";
        return QByteArray();
    }
    
    // Convert QR code matrix to raw image data
    int size = qrcode->width * qrcode->width;
    QByteArray result(reinterpret_cast<const char*>(qrcode->data), size);
    
    // Store QR metadata in the first few bytes for reconstruction
    QByteArray metadata;
    QDataStream metaStream(&metadata, QIODevice::WriteOnly);
    metaStream << static_cast<qint32>(qrcode->width) << static_cast<qint32>(qrcode->version);
    
    QRcode_free(qrcode);
    
    // Prepend metadata to result
    return metadata + result;
}

TOTPEnrollmentData TOTPQRGenerator::decodeTOTPQRCode(const QByteArray& qrData) {
    // In a real implementation, this would use a QR decoder library
    // For now, we'll return an empty struct since this is mainly for testing
    qWarning() << "TOTPQRGenerator: QR decoding not implemented in this version";
    return TOTPEnrollmentData{};
}

// ============================================================================
// TOTPEnrollment Implementation
// ============================================================================

TOTPEnrollment::TOTPEnrollment(QObject* parent)
    : QObject(parent)
    , qrGenerator_(std::make_unique<TOTPQRGenerator>(this))
    , qrTimeout_(300)  // 5 minutes default timeout
{
}

QString TOTPEnrollment::generateSecret() const {
    // Generate 160-bit (20-byte) secret for HMAC-SHA1 compatibility
    QByteArray randomBytes(20, 0);
    
    // Use OpenSSL's cryptographically secure random generator
    if (RAND_bytes(reinterpret_cast<unsigned char*>(randomBytes.data()), 20) != 1) {
        throw std::runtime_error("Failed to generate cryptographically secure random bytes");
    }
    
    // Encode to Base32 (RFC 4648)
    return encodeBase32(randomBytes);
}

QString TOTPEnrollment::createOTPAuthURL(const QString& issuer, 
                                       const QString& accountName, 
                                       const QString& secret) const {
    // Validate inputs
    if (issuer.isEmpty() || accountName.isEmpty() || secret.isEmpty()) {
        qWarning() << "TOTPEnrollment: Invalid parameters for OTP auth URL";
        return QString();
    }
    
    if (!isValidBase32(secret)) {
        qWarning() << "TOTPEnrollment: Invalid Base32 secret";
        return QString();
    }
    
    // Create industry-standard otpauth:// URL
    QString url = QString("otpauth://totp/%1:%2?secret=%3&issuer=%4&algorithm=SHA1&digits=6&period=30")
                  .arg(QUrl::toPercentEncoding(issuer).constData())
                  .arg(QUrl::toPercentEncoding(accountName).constData())
                  .arg(secret)
                  .arg(QUrl::toPercentEncoding(issuer).constData());
    
    return url;
}

TOTPEnrollmentData TOTPEnrollment::createEnrollmentData(const QString& issuer,
                                                       const QString& accountName, 
                                                       const QString& secret) {
    try {
        // Validate inputs
        if (issuer.isEmpty() || accountName.isEmpty() || secret.isEmpty()) {
            throw std::invalid_argument("Missing required enrollment parameters");
        }
        
        // Create enrollment data
        TOTPEnrollmentData data;
        data.issuer = issuer;
        data.accountName = accountName;
        data.secret = secret;
        data.otpauthURL = createOTPAuthURL(issuer, accountName, secret);
        data.timestamp = QDateTime::currentSecsSinceEpoch();
        
        // Generate verification code using the secret
        TOTP totp(secret.toStdString());
        data.verificationCode = QString::fromStdString(totp.generate());
        
        if (data.otpauthURL.isEmpty()) {
            throw std::runtime_error("Failed to create OTP auth URL");
        }
        
        return data;
        
    } catch (const std::exception& e) {
        qWarning() << "TOTPEnrollment: Failed to create enrollment data:" << e.what();
        return TOTPEnrollmentData{}; // Return invalid data
    }
}

QByteArray TOTPEnrollment::generateEnrollmentQR(const TOTPEnrollmentData& enrollmentData) {
    if (!enrollmentData.isValid()) {
        emit enrollmentFailed("Invalid enrollment data");
        return QByteArray();
    }
    
    if (enrollmentData.isExpired(qrTimeout_)) {
        emit enrollmentFailed("Enrollment data has expired");
        return QByteArray();
    }
    
    try {
        QByteArray qrData = qrGenerator_->generateTOTPQRCode(enrollmentData);
        
        if (qrData.isEmpty()) {
            emit enrollmentFailed("Failed to generate QR code");
            return QByteArray();
        }
        
        emit enrollmentQRGenerated(qrData, enrollmentData);
        return qrData;
        
    } catch (const std::exception& e) {
        QString error = QString("QR generation failed: %1").arg(e.what());
        emit enrollmentFailed(error);
        return QByteArray();
    }
}

bool TOTPEnrollment::verifySetupCode(const QString& secret, const QString& userCode, 
                                    int timeWindowTolerance) const {
    if (secret.isEmpty() || userCode.isEmpty()) {
        qWarning() << "TOTPEnrollment: Empty secret or user code";
        return false;
    }
    
    if (!isValidBase32(secret)) {
        qWarning() << "TOTPEnrollment: Invalid Base32 secret";
        return false;
    }
    
    // Validate user code format (should be 6 digits)
    if (userCode.length() != 6) {
        qWarning() << "TOTPEnrollment: User code must be 6 digits";
        return false;
    }
    
    bool isNumber;
    userCode.toInt(&isNumber);
    if (!isNumber) {
        qWarning() << "TOTPEnrollment: User code must be numeric";
        return false;
    }
    
    try {
        TOTP totp(secret.toStdString());
        qint64 currentTime = QDateTime::currentSecsSinceEpoch();
        
        // Check current time window and surrounding windows for clock skew tolerance
        for (int offset = -timeWindowTolerance; offset <= timeWindowTolerance; ++offset) {
            qint64 timeToCheck = currentTime + (offset * 30); // 30-second time step
            QString expectedCode = QString::fromStdString(totp.generate(timeToCheck));
            
            if (userCode == expectedCode) {
                qDebug() << "TOTPEnrollment: Code verified successfully" 
                         << (offset == 0 ? "" : QString(" (offset: %1)").arg(offset));
                return true;
            }
        }
        
        qDebug() << "TOTPEnrollment: Code verification failed";
        return false;
        
    } catch (const std::exception& e) {
        qWarning() << "TOTPEnrollment: Verification failed:" << e.what();
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

QByteArray TOTPEnrollment::decodeBase32(const QString& encoded) const {
    auto val = [](char c) -> int {
        if ('A' <= c && c <= 'Z') return c - 'A';
        if ('a' <= c && c <= 'z') return c - 'a';
        if ('2' <= c && c <= '7') return c - '2' + 26;
        return -1;
    };
    
    QByteArray result;
    int buffer = 0;
    int bitsLeft = 0;
    
    for (QChar qc : encoded) {
        char c = qc.toLatin1();
        int v = val(c);
        if (v < 0) continue; // Skip invalid characters
        
        buffer = (buffer << 5) | v;
        bitsLeft += 5;
        
        if (bitsLeft >= 8) {
            bitsLeft -= 8;
            result.append(static_cast<char>((buffer >> bitsLeft) & 0xFF));
        }
    }
    
    return result;
}

bool TOTPEnrollment::isValidBase32(const QString& encoded) const {
    if (encoded.isEmpty()) return false;
    
    // Check for valid Base32 characters only
    for (QChar c : encoded) {
        char ch = c.toLatin1();
        bool valid = (ch >= 'A' && ch <= 'Z') || 
                    (ch >= 'a' && ch <= 'z') || 
                    (ch >= '2' && ch <= '7') ||
                    ch == '='; // Padding character
        if (!valid) return false;
    }
    
    return true;
} 