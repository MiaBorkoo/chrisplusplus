#pragma once

#include <QString>
#include <QDateTime>
#include <QVector>

// Forward declaration
class DeviceCertificate;

// Constants for verification methods
namespace VerificationMethod {
    static const QString TOFU = "tofu";
    static const QString QR_CODE = "qr_code";
    static const QString VOICE = "voice";
    static const QString UPDATE = "update";
    static const QString TOFU_DECISION = "tofu_decision";
}

enum class TrustLevel {
    Untrusted,
    TOFU,           // Trusted on first use
    OOBVerified     // Out-of-band verified
};

struct VerificationEvent {
    QDateTime timestamp;
    QString method;        // "tofu", "qr_code", "voice"
    QString deviceId;      
    bool success;
    QString details;       // Additional verification details
};

struct TrustCheckResult {
    bool isTrusted;
    TrustLevel trust_level;
    QVector<DeviceCertificate> certificates;
    bool requires_tofu_prompt;
};

class TrustStoreEntry {
public:
    TrustStoreEntry();
    explicit TrustStoreEntry(const QString& userId);

    // Getters
    QString userId() const { return userId_; }
    QVector<DeviceCertificate> deviceCertificates() const { return deviceCertificates_; }
    TrustLevel trustLevel() const { return trustLevel_; }
    QDateTime trustedAt() const { return trustedAt_; }
    QVector<VerificationEvent> verificationHistory() const { return verificationHistory_; }

    // Trust management
    bool addDeviceCertificate(const DeviceCertificate& cert);
    bool removeDeviceCertificate(const QString& deviceId);
    bool updateDeviceCertificate(const DeviceCertificate& cert);
    
    void setTrustLevel(TrustLevel level);
    void addVerificationEvent(const VerificationEvent& event);

    // Certificate lookup
    DeviceCertificate findCertificate(const QString& deviceId) const;
    bool hasDevice(const QString& deviceId) const;

    // Trust verification
    bool isDeviceTrusted(const QString& deviceId) const;
    bool requiresVerification() const;

    // Serialization
    QByteArray serialize() const;
    static TrustStoreEntry deserialize(const QByteArray& data);

private:
    QString userId_;
    QVector<DeviceCertificate> deviceCertificates_;
    TrustLevel trustLevel_;
    QDateTime trustedAt_;
    QVector<VerificationEvent> verificationHistory_;
}; 