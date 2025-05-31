#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include "DeviceCertificate.h"

// Verification data struct
struct QRVerificationData {
    QString userId;
    QString deviceId;
    QByteArray publicKeyFingerprint;
    QString verificationCode;  // Random code 
    qint64 timestamp;        
    
    // Serialization
    QByteArray serialize() const;
    static QRVerificationData deserialize(const QByteArray& data);
};

class QRVerification : public QObject {
    Q_OBJECT
public:
    explicit QRVerification(QObject* parent = nullptr);
    
    // Generate QR code data for a certificate
    QRVerificationData generateVerificationData(const DeviceCertificate& cert);
    
    // Verify received QR code data
    bool verifyReceivedData(const QRVerificationData& received,
                           const DeviceCertificate& localCert);
    
    // Generate and verify the actual QR code image
    QByteArray generateQRCode(const QRVerificationData& data);
    QRVerificationData decodeQRCode(const QByteArray& qrImage);
    
    // Configuration
    void setVerificationTimeout(int seconds) { verificationTimeout_ = seconds; }
    int verificationTimeout() const { return verificationTimeout_; }

signals:
    void verificationSucceeded(const QString& userId, const QString& deviceId);
    void verificationFailed(const QString& userId, const QString& error);

private:
    int verificationTimeout_;  // Timeout in seconds
    
    // Helper methods
    QByteArray calculateFingerprint(const QByteArray& publicKey);
    QString generateVerificationCode();
    bool isVerificationExpired(qint64 timestamp) const;
}; 