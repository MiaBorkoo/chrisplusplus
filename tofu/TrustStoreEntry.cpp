#include "TrustStoreEntry.h"
#include "DeviceCertificate.h"
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>

TrustStoreEntry::TrustStoreEntry()
    : trustLevel_(TrustLevel::Untrusted)
{
}

TrustStoreEntry::TrustStoreEntry(const QString& userId)
    : userId_(userId)
    , trustLevel_(TrustLevel::Untrusted)
{
}

bool TrustStoreEntry::addDeviceCertificate(const DeviceCertificate& cert) {
    // Verify the certificate first
    if (!cert.verify()) {
        return false;
    }

    // Check if device already exists
    if (hasDevice(cert.deviceId())) {
        return false;
    }

    // Add the certificate
    deviceCertificates_.append(cert);

    // If this is the first device, mark as TOFU
    if (deviceCertificates_.size() == 1 && trustLevel_ == TrustLevel::Untrusted) {
        trustLevel_ = TrustLevel::TOFU;
        trustedAt_ = QDateTime::currentDateTimeUtc();

        // Record the TOFU event
        VerificationEvent event;
        event.timestamp = trustedAt_;
        event.method = "tofu";
        event.deviceId = cert.deviceId();
        event.success = true;
        event.details = "Initial device trust";
        verificationHistory_.append(event);
    }

    return true;
}

bool TrustStoreEntry::removeDeviceCertificate(const QString& deviceId) {
    for (int i = 0; i < deviceCertificates_.size(); ++i) {
        if (deviceCertificates_[i].deviceId() == deviceId) {
            deviceCertificates_.removeAt(i);
            return true;
        }
    }
    return false;
}

bool TrustStoreEntry::updateDeviceCertificate(const DeviceCertificate& cert) {
    // Verify the new certificate
    if (!cert.verify()) {
        return false;
    }

    // Find and update the existing certificate
    for (int i = 0; i < deviceCertificates_.size(); ++i) {
        if (deviceCertificates_[i].deviceId() == cert.deviceId()) {
            // Record the update event
            VerificationEvent event;
            event.timestamp = QDateTime::currentDateTimeUtc();
            event.method = "update";
            event.deviceId = cert.deviceId();
            event.success = true;
            event.details = "Certificate updated";
            verificationHistory_.append(event);

            deviceCertificates_[i] = cert;
            return true;
        }
    }
    return false;
}

void TrustStoreEntry::setTrustLevel(TrustLevel level) {
    if (trustLevel_ != level) {
        trustLevel_ = level;
        if (level != TrustLevel::Untrusted) {
            trustedAt_ = QDateTime::currentDateTimeUtc();
        }
    }
}

void TrustStoreEntry::addVerificationEvent(const VerificationEvent& event) {
    verificationHistory_.append(event);

    // Update trust level based on verification method
    if (event.success) {
        if (event.method == "qr_code" || event.method == "voice") {
            trustLevel_ = TrustLevel::OOBVerified;
        }
    }
}

DeviceCertificate TrustStoreEntry::findCertificate(const QString& deviceId) const {
    for (const auto& cert : deviceCertificates_) {
        if (cert.deviceId() == deviceId) {
            return cert;
        }
    }
    return DeviceCertificate();
}

bool TrustStoreEntry::hasDevice(const QString& deviceId) const {
    return !findCertificate(deviceId).deviceId().isEmpty();
}

bool TrustStoreEntry::isDeviceTrusted(const QString& deviceId) const {
    // Device must exist and have a valid certificate
    DeviceCertificate cert = findCertificate(deviceId);
    if (cert.deviceId().isEmpty() || !cert.verify()) {
        return false;
    }

    // Check trust level
    if (trustLevel_ == TrustLevel::Untrusted) {
        return false;
    }

    // Check certificate expiration
    if (cert.expiresAt() < QDateTime::currentDateTimeUtc()) {
        return false;
    }

    return true;
}

bool TrustStoreEntry::requiresVerification() const {
    return trustLevel_ == TrustLevel::TOFU;
}

QByteArray TrustStoreEntry::serialize() const {
    QJsonObject obj;
    obj["user_id"] = userId_;
    obj["trust_level"] = static_cast<int>(trustLevel_);
    obj["trusted_at"] = trustedAt_.toString(Qt::ISODate);

    // Serialize certificates
    QJsonArray certArray;
    for (const auto& cert : deviceCertificates_) {
        certArray.append(QString::fromLatin1(cert.serialize().toBase64()));
    }
    obj["device_certificates"] = certArray;

    // Serialize verification history
    QJsonArray historyArray;
    for (const auto& event : verificationHistory_) {
        QJsonObject eventObj;
        eventObj["timestamp"] = event.timestamp.toString(Qt::ISODate);
        eventObj["method"] = event.method;
        eventObj["device_id"] = event.deviceId;
        eventObj["success"] = event.success;
        eventObj["details"] = event.details;
        historyArray.append(eventObj);
    }
    obj["verification_history"] = historyArray;

    QJsonDocument doc(obj);
    return doc.toJson(QJsonDocument::Compact);
}

TrustStoreEntry TrustStoreEntry::deserialize(const QByteArray& data) {
    TrustStoreEntry entry;
    QJsonDocument doc = QJsonDocument::fromJson(data);
    
    if (doc.isObject()) {
        QJsonObject obj = doc.object();
        entry.userId_ = obj["user_id"].toString();
        entry.trustLevel_ = static_cast<TrustLevel>(obj["trust_level"].toInt());
        entry.trustedAt_ = QDateTime::fromString(obj["trusted_at"].toString(), Qt::ISODate);

        // Deserialize certificates
        QJsonArray certArray = obj["device_certificates"].toArray();
        for (const auto& certValue : certArray) {
            QByteArray certData = QByteArray::fromBase64(certValue.toString().toLatin1());
            entry.deviceCertificates_.append(DeviceCertificate::deserialize(certData));
        }

        // Deserialize verification history
        QJsonArray historyArray = obj["verification_history"].toArray();
        for (const auto& eventValue : historyArray) {
            QJsonObject eventObj = eventValue.toObject();
            VerificationEvent event;
            event.timestamp = QDateTime::fromString(eventObj["timestamp"].toString(), Qt::ISODate);
            event.method = eventObj["method"].toString();
            event.deviceId = eventObj["device_id"].toString();
            event.success = eventObj["success"].toBool();
            event.details = eventObj["details"].toString();
            entry.verificationHistory_.append(event);
        }
    }

    return entry;
} 