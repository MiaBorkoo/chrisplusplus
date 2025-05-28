#pragma once

#include <QString>
#include <QDateTime>
#include <QList>
#include <openssl/evp.h>
#include "TrustStoreEntry.h"

// RAII wrapper for EVP_PKEY
class ScopedEVP_PKEY {
public:
    explicit ScopedEVP_PKEY(EVP_PKEY* pkey = nullptr) : pkey_(pkey) {}
    ~ScopedEVP_PKEY() { if (pkey_) EVP_PKEY_free(pkey_); }
    EVP_PKEY* get() { return pkey_; }
    EVP_PKEY** ptr() { return &pkey_; }
    operator bool() const { return pkey_ != nullptr; }
private:
    EVP_PKEY* pkey_;
};

// RAII wrapper for EVP_MD_CTX
class ScopedEVP_MD_CTX {
public:
    ScopedEVP_MD_CTX() : ctx_(EVP_MD_CTX_new()) {}
    ~ScopedEVP_MD_CTX() { if (ctx_) EVP_MD_CTX_free(ctx_); }
    EVP_MD_CTX* get() { return ctx_; }
    operator bool() const { return ctx_ != nullptr; }
private:
    EVP_MD_CTX* ctx_;
};

class DeviceCertificate {
public:
    DeviceCertificate();
    ~DeviceCertificate();

    // Getters
    QString userId() const { return userId_; }
    QString deviceId() const { return deviceId_; }
    QByteArray identityPublicKey() const { return identityPublicKey_; }
    QDateTime createdAt() const { return createdAt_; }
    QDateTime expiresAt() const { return expiresAt_; }
    QByteArray selfSignature() const { return selfSignature_; }

    // Setters
    void setUserId(const QString& userId) { userId_ = userId; }
    void setDeviceId(const QString& deviceId) { deviceId_ = deviceId; }
    void setIdentityPublicKey(const QByteArray& key) { identityPublicKey_ = key; }
    void setCreatedAt(const QDateTime& timestamp) { createdAt_ = timestamp; }
    void setExpiresAt(const QDateTime& timestamp) { expiresAt_ = timestamp; }
    void setSelfSignature(const QByteArray& signature) { selfSignature_ = signature; }

    // Certificate operations
    bool verify() const;
    QByteArray sign(const QByteArray& privateKey);
    static DeviceCertificate generate(const QString& userId, const QString& deviceId, 
                                    const QByteArray& privateKey, const QByteArray& publicKey);

    // Comparison operators
    bool operator==(const DeviceCertificate& other) const;
    bool operator!=(const DeviceCertificate& other) const { return !(*this == other); }

    // Validators
    bool isExpired() const;
    bool isValid() const;

    // Serialization
    QByteArray serialize() const;
    static DeviceCertificate deserialize(const QByteArray& data);

private:
    QString userId_;
    QString deviceId_;
    QByteArray identityPublicKey_;  // Ed25519 public key
    QDateTime createdAt_;
    QDateTime expiresAt_;
    QByteArray selfSignature_;      // Ed25519 signature

    // Helper methods
    QByteArray computeCertificateData() const;
}; 