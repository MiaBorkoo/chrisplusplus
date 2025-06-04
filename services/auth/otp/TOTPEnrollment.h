#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <memory>
#include "TOTP.h"

// Clean TOTP enrollment data structure - no dependencies on TOFU certificates
struct TOTPEnrollmentData {
    QString issuer;           // "MyShare"
    QString accountName;      // "user@example.com"  
    QString secret;           // Base32-encoded secret
    QString otpauthURL;       // Full otpauth:// URL
    qint64 timestamp;         // For timeout protection
    QString verificationCode; // 6-digit code for initial verification
    
    // Clean serialization
    QByteArray serialize() const;
    static TOTPEnrollmentData deserialize(const QByteArray& data);
    bool isValid() const;
    bool isExpired(int timeoutSeconds = 300) const;
};

class TOTPQRGenerator : public QObject {
    Q_OBJECT
public:
    explicit TOTPQRGenerator(QObject* parent = nullptr);
    ~TOTPQRGenerator() = default;
    
    // Generate QR code for TOTP enrollment using proven qrencode approach
    QByteArray generateTOTPQRCode(const TOTPEnrollmentData& data);
    
    // Decode QR code back to enrollment data (for testing/validation)
    TOTPEnrollmentData decodeTOTPQRCode(const QByteArray& qrData);
    
    // Configuration
    void setErrorCorrectionLevel(int level) { errorCorrectionLevel_ = level; }
    int errorCorrectionLevel() const { return errorCorrectionLevel_; }

private:
    int errorCorrectionLevel_;  // QR error correction level (0-3, default 3 = highest)
};

class TOTPEnrollment : public QObject {
    Q_OBJECT
public:
    explicit TOTPEnrollment(QObject* parent = nullptr);
    
    // Step 1: Generate cryptographically secure TOTP secret (160-bit for HMAC-SHA1)
    QString generateSecret() const;
    
    // Step 2: Create industry-standard otpauth:// URL
    QString createOTPAuthURL(const QString& issuer, 
                           const QString& accountName, 
                           const QString& secret) const;
    
    // Step 3: Generate enrollment data and QR code
    TOTPEnrollmentData createEnrollmentData(const QString& issuer,
                                          const QString& accountName, 
                                          const QString& secret);
    
    QByteArray generateEnrollmentQR(const TOTPEnrollmentData& enrollmentData);
    
    // Step 4: Verify user-entered setup code with time window tolerance
    bool verifySetupCode(const QString& secret, const QString& userCode, 
                        int timeWindowTolerance = 1) const;
    
    // Configuration
    void setQRTimeout(int seconds) { qrTimeout_ = seconds; }
    int qrTimeout() const { return qrTimeout_; }

signals:
    void enrollmentQRGenerated(const QByteArray& qrData, const TOTPEnrollmentData& enrollmentData);
    void setupCodeVerified(bool success);
    void enrollmentFailed(const QString& error);

private:
    std::unique_ptr<TOTPQRGenerator> qrGenerator_;
    int qrTimeout_;  // Enrollment timeout (default 5 minutes)
    
    // Helper methods
    QByteArray encodeBase32(const QByteArray& data) const;
    QByteArray decodeBase32(const QString& encoded) const;
    bool isValidBase32(const QString& encoded) const;
}; 