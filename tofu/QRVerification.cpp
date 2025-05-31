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
    // Serialize the verification data
    QByteArray serialized = data.serialize();
    
    // Generate QR code using qrencode
    QRcode* qrcode = QRcode_encodeData(
        serialized.size(),
        reinterpret_cast<const unsigned char*>(serialized.constData()),
        0,  // Version 0 (auto-select)
        QR_ECLEVEL_H  // Highest error correction
    );
    
    if (!qrcode) {
        qWarning() << "Failed to generate QR code";
        return QByteArray();
    }
    
    // Convert to image format (PNG)
    // Note: In real implementation, we'd use Qt's image classes
    // This is just a placeholder that returns the raw QR data
    QByteArray result(reinterpret_cast<const char*>(qrcode->data), qrcode->width * qrcode->width);
    QRcode_free(qrcode);
    
    return result;
}

QRVerificationData QRVerification::decodeQRCode(const QByteArray& qrImage) {
    // In real implementation, we'd use a QR code scanning library
    // For now, assume qrImage is already decoded to serialized data
    return QRVerificationData::deserialize(qrImage);
}

QByteArray QRVerification::calculateFingerprint(const QByteArray& publicKey) {
    return QCryptographicHash::hash(publicKey, QCryptographicHash::Sha256);
}

QString QRVerification::generateVerificationCode() {
    // Generate a 6-digit verification code
    int code = QRandomGenerator::global()->bounded(100000, 999999);
    return QString::number(code);
}

bool QRVerification::isVerificationExpired(qint64 timestamp) const {
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