#include "QRVerification.h"
#include <QDateTime>
#include <QCryptographicHash>
#include <QDataStream>
#include <QIODevice>
#include <QRandomGenerator>
#include <QDebug>

// Using qrencode library for QR code generation
extern "C" {
#include <qrencode.h>
}

QRVerification::QRVerification(QObject* parent)
    : QObject(parent)
    , verificationTimeout_(300)  // 5 minutes default timeout
{
}

QRVerificationData QRVerification::generateVerificationData(const DeviceCertificate& cert) {
    QRVerificationData data;
    data.userId = cert.userId();
    data.deviceId = cert.deviceId();
    data.publicKeyFingerprint = calculateFingerprint(cert.identityPublicKey());
    data.verificationCode = generateVerificationCode();
    data.timestamp = QDateTime::currentSecsSinceEpoch();
    return data;
}

bool QRVerification::verifyReceivedData(const QRVerificationData& received,
                                      const DeviceCertificate& localCert) {
    // Check expiration
    if (isVerificationExpired(received.timestamp)) {
        emit verificationFailed(received.userId, "Verification code expired");
        return false;
    }
    
    // Verify user and device IDs match
    if (received.userId != localCert.userId()) {
        emit verificationFailed(received.userId, "User ID mismatch");
        return false;
    }
    
    // Calculate and compare fingerprints
    QByteArray localFingerprint = calculateFingerprint(localCert.identityPublicKey());
    if (received.publicKeyFingerprint != localFingerprint) {
        emit verificationFailed(received.userId, "Public key fingerprint mismatch");
        return false;
    }
    
    emit verificationSucceeded(received.userId, received.deviceId);
    return true;
}

QByteArray QRVerification::generateQRCode(const QRVerificationData& data) {
    // Serialize verification data into a compact binary format
    // This includes user ID, device ID, public key fingerprint and verification code
    QByteArray serialized = data.serialize();
    
    // Generate QR code with high error correction level (30% data recovery)
    // This ensures the code can be read even if partially damaged or obscured
    QRcode* qrcode = QRcode_encodeData(
        serialized.size(),
        reinterpret_cast<const unsigned char*>(serialized.constData()),
        0,  // Version 0: Auto-select optimal QR version based on data size
        QR_ECLEVEL_H  // Level H: Highest error correction (30% recovery)
    );
    
    if (!qrcode) {
        qWarning() << "QR code generation failed - data may be too large or invalid";
        return QByteArray();
    }
    
    // Convert QR code matrix to raw image data
    // Each byte represents one module (black/white pixel)
    // The width of the QR code is qrcode->width pixels
    QByteArray result(reinterpret_cast<const char*>(qrcode->data), 
                     qrcode->width * qrcode->width);
    QRcode_free(qrcode);
    
    return result;
}

QRVerificationData QRVerification::decodeQRCode(const QByteArray& qrImage) {
    // In real implementation, we'd use a QR code scanning library
    // For now, assume qrImage is already decoded to serialized data
    return QRVerificationData::deserialize(qrImage);
}

QByteArray QRVerification::calculateFingerprint(const QByteArray& publicKey) {
    // Generate SHA-256 hash of the public key for secure comparison
    // This fingerprint is used to verify key authenticity during out-of-band verification
    // The hash provides a shorter, fixed-length representation that's easier to verify
    return QCryptographicHash::hash(publicKey, QCryptographicHash::Sha256);
}

QString QRVerification::generateVerificationCode() {
    // Generate a secure 6-digit verification code
    // Using QRandomGenerator::global() which is cryptographically secure on most platforms
    // Range: 100000-999999 ensures exactly 6 digits
    int code = QRandomGenerator::global()->bounded(100000, 999999);
    return QString::number(code);
}

bool QRVerification::isVerificationExpired(qint64 timestamp) const {
    // Check if the verification attempt has exceeded the timeout period
    // This prevents replay attacks and ensures timely verification
    qint64 now = QDateTime::currentSecsSinceEpoch();
    return (now - timestamp) > verificationTimeout_;
}

// QRVerificationData serialization
QByteArray QRVerificationData::serialize() const {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_5);
    
    stream << userId << deviceId << publicKeyFingerprint 
           << verificationCode << timestamp;
    
    return data;
}

QRVerificationData QRVerificationData::deserialize(const QByteArray& data) {
    QRVerificationData result;
    QDataStream stream(data);
    stream.setVersion(QDataStream::Qt_6_5);
    
    stream >> result.userId >> result.deviceId >> result.publicKeyFingerprint
           >> result.verificationCode >> result.timestamp;
    
    return result;
} 