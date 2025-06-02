#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <memory>
#include "../../../tofu/QRVerification.h"  // Reuse TOFU's QR infrastructure
#include "TOTP.h"                          // Your existing TOTP class

// Data structure for TOTP enrollment QR codes
struct TOTPEnrollmentData {
    QString issuer;           // "MyShare"
    QString accountName;      // "user@example.com"  
    QString secret;           // Base32-encoded secret
    QString otpauthURL;       // Full otpauth:// URL
    qint64 timestamp;         // For timeout protection (reuse TOFU's anti-replay)
    
    // Serialization (reuse TOFU's secure serialization pattern)
    QByteArray serialize() const;
    static TOTPEnrollmentData deserialize(const QByteArray& data);
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
    
    // Step 3: Generate QR code (reuses TOFU's secure QR generation)
    QByteArray generateEnrollmentQR(const QString& issuer,
                                   const QString& accountName, 
                                   const QString& secret);
    
    // Step 4: Verify user-entered setup code
    bool verifySetupCode(const QString& secret, const QString& userCode) const;
    
    // Configuration (same pattern as TOFU)
    void setQRTimeout(int seconds) { qrTimeout_ = seconds; }
    int qrTimeout() const { return qrTimeout_; }

signals:
    void enrollmentQRGenerated(const QByteArray& qrData);
    void setupCodeVerified(bool success);
    void enrollmentFailed(const QString& error);

private:
    std::unique_ptr<QRVerification> qrGenerator_;  // Reuse TOFU's QR infrastructure
    int qrTimeout_;                                // Anti-replay timeout (like TOFU)
    
    // Helper methods
    QByteArray encodeBase32(const QByteArray& data) const;  // RFC 4648 base32 encoding
    bool isEnrollmentExpired(qint64 timestamp) const;       // Reuse TOFU's timeout logic
}; 