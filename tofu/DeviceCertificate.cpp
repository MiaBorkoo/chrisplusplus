#include "DeviceCertificate.h"
#include <QDataStream>
#include <QIODevice>
#include <openssl/evp.h>
#include <openssl/err.h>

/**
 * @class DeviceCertificate
 * @brief Manages device certificate operations.
 * @author jjola00
 *
 * This class handles device certificate operations.
 */

DeviceCertificate::DeviceCertificate() {
    createdAt_ = QDateTime::currentDateTimeUtc();
    // Default expiration is 1 year
    expiresAt_ = createdAt_.addYears(1);
}

DeviceCertificate::~DeviceCertificate() = default;

bool DeviceCertificate::verify() const {
    if (identityPublicKey_.isEmpty() || selfSignature_.isEmpty()) {
        return false;
    }

    // Create and load public key
    ScopedEVP_PKEY pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(identityPublicKey_.constData()),
        identityPublicKey_.size()));
    
    if (!pkey) {
        return false;
    }

    // Get data to verify
    QByteArray data = computeCertificateData();

    // Verify signature
    ScopedEVP_MD_CTX md_ctx;
    if (!md_ctx) return false;

    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        return false;
    }

    return (EVP_DigestVerify(md_ctx.get(),
        reinterpret_cast<const unsigned char*>(selfSignature_.constData()),
        selfSignature_.size(),
        reinterpret_cast<const unsigned char*>(data.constData()),
        data.size()) == 1);
}

QByteArray DeviceCertificate::sign(const QByteArray& privateKey) {
    if (privateKey.isEmpty()) return QByteArray();

    // Create and load private key
    ScopedEVP_PKEY pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(privateKey.constData()),
        privateKey.size()));
    
    if (!pkey) return QByteArray();

    QByteArray data = computeCertificateData();
    
    // Sign the data
    ScopedEVP_MD_CTX md_ctx;
    if (!md_ctx) return QByteArray();

    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        return QByteArray();
    }

    // Get required signature length
    size_t siglen;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &siglen,
        reinterpret_cast<const unsigned char*>(data.constData()),
        data.size()) != 1) {
        return QByteArray();
    }

    QByteArray signature(siglen, 0);
    if (EVP_DigestSign(md_ctx.get(),
        reinterpret_cast<unsigned char*>(signature.data()),
        &siglen,
        reinterpret_cast<const unsigned char*>(data.constData()),
        data.size()) != 1) {
        return QByteArray();
    }

    selfSignature_ = signature;
    return signature;
}

bool DeviceCertificate::operator==(const DeviceCertificate& other) const {
    return userId_ == other.userId_ &&
           deviceId_ == other.deviceId_ &&
           identityPublicKey_ == other.identityPublicKey_ &&
           createdAt_ == other.createdAt_ &&
           expiresAt_ == other.expiresAt_ &&
           selfSignature_ == other.selfSignature_;
}

QByteArray DeviceCertificate::computeCertificateData() const {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << userId_;
    stream << deviceId_;
    stream << identityPublicKey_;
    stream << createdAt_;
    stream << expiresAt_;
    return data;
}

bool DeviceCertificate::isExpired() const {
    return QDateTime::currentDateTimeUtc() > expiresAt_;
}

bool DeviceCertificate::isValid() const {
    if (userId_.isEmpty() || deviceId_.isEmpty() || 
        identityPublicKey_.isEmpty() || selfSignature_.isEmpty()) {
        return false;
    }

    // Check expiration
    if (isExpired()) {
        return false;
    }

    // Verify signature
    return verify();
}

DeviceCertificate DeviceCertificate::generate(
    const QString& userId, 
    const QString& deviceId,
    const QByteArray& privateKey,
    const QByteArray& publicKey)
{
    if (userId.isEmpty() || deviceId.isEmpty() || 
        privateKey.isEmpty() || publicKey.isEmpty()) {
        return DeviceCertificate();
    }

    DeviceCertificate cert;
    cert.setUserId(userId);
    cert.setDeviceId(deviceId);
    cert.setIdentityPublicKey(publicKey);
    cert.setCreatedAt(QDateTime::currentDateTimeUtc());
    cert.setExpiresAt(cert.createdAt().addYears(1));  // 1 year validity

    // Sign the certificate
    if (!cert.sign(privateKey).isEmpty()) {
        return cert;
    }

    // Return empty certificate if signing fails
    return DeviceCertificate();
}

QByteArray DeviceCertificate::serialize() const {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    
    // Write all certificate fields
    stream << userId_;
    stream << deviceId_;
    stream << identityPublicKey_;
    stream << createdAt_;
    stream << expiresAt_;
    stream << selfSignature_;
    
    return data;
}

DeviceCertificate DeviceCertificate::deserialize(const QByteArray& data) {
    DeviceCertificate cert;
    if (data.isEmpty()) return cert;
    
    QDataStream stream(data);
    
    // Read all certificate fields
    stream >> cert.userId_;
    stream >> cert.deviceId_;
    stream >> cert.identityPublicKey_;
    stream >> cert.createdAt_;
    stream >> cert.expiresAt_;
    stream >> cert.selfSignature_;
    
    // Verify the certificate after deserialization
    if (!cert.verify()) {
        return DeviceCertificate();
    }
    
    return cert;
} 