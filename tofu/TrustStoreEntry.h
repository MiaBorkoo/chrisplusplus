#pragma once

#include <QString>
#include <QDateTime>
#include <QVector>

// Forward declaration
class DeviceCertificate;

/**
 * @brief Represents the trust level for a user's devices
 */
enum class TrustLevel {
    Untrusted,
    TOFU,           // Trusted on first use
    OOBVerified     // Out-of-band verified
};

/**
 * @brief Represents a verification event in the trust history
 */
struct VerificationEvent {
    QDateTime timestamp;
    QString method;        // "tofu", "qr_code", "voice"
    QString deviceId;      // Device that performed verification
    bool success;
    QString details;       // Additional verification details
};

/**
 * @brief Result of a trust check operation
 */
struct TrustCheckResult {
    bool isTrusted;
    TrustLevel trust_level;
    QVector<DeviceCertificate> certificates;
    bool requires_tofu_prompt;
};

/**
 * @brief Manages trust information for a user's devices
 * 
 * This class implements the TrustStoreEntry structure as defined in the project requirements.
 * It maintains a list of device certificates and their trust status.
 */
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