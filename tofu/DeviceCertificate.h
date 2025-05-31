#pragma once

#include <QString>
#include <QDateTime>
#include <QList>
#include <openssl/evp.h>
#include "TrustStoreEntry.h"

// Constants for validation
constexpr int MAX_USER_ID_LENGTH = 128;
constexpr int MAX_DEVICE_ID_LENGTH = 64;
constexpr int ED25519_KEY_SIZE = 32;
constexpr int ED25519_SIG_SIZE = 64;
constexpr int CERT_VERSION = 1;  // For serialization versioning

// Error codes for certificate operations
enum class CertError {
    None,
    InvalidUserId,
    InvalidDeviceId,
    InvalidPublicKey,
    InvalidSignature,
    ExpiredCertificate,
    SerializationError,
    ValidationError
};

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
    // Prevent copying
    ScopedEVP_PKEY(const ScopedEVP_PKEY&) = delete;
    ScopedEVP_PKEY& operator=(const ScopedEVP_PKEY&) = delete;
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
    // Prevent copying
    ScopedEVP_MD_CTX(const ScopedEVP_MD_CTX&) = delete;
    ScopedEVP_MD_CTX& operator=(const ScopedEVP_MD_CTX&) = delete;
};

class DeviceCertificate {
public:
    DeviceCertificate();
    ~DeviceCertificate();

    // Copy semantics
    DeviceCertificate(const DeviceCertificate&) = default;
    DeviceCertificate& operator=(const DeviceCertificate&) = default;

    // Getters
    QString userId() const { return userId_; }
    QString deviceId() const { return deviceId_; }
    QByteArray identityPublicKey() const { return identityPublicKey_; }
    QDateTime createdAt() const { return createdAt_; }
    QDateTime expiresAt() const { return expiresAt_; }
    QByteArray selfSignature() const { return selfSignature_; }
    CertError lastError() const { return lastError_; }
    QString errorString() const { return errorString_; }

    // Setters with validation
    bool setUserId(const QString& userId);
    bool setDeviceId(const QString& deviceId);
    bool setIdentityPublicKey(const QByteArray& key);
    void setCreatedAt(const QDateTime& timestamp) { createdAt_ = timestamp; }
    void setExpiresAt(const QDateTime& timestamp) { expiresAt_ = timestamp; }
    void setSelfSignature(const QByteArray& signature);

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
    bool validateFields() const;  // New method for field validation

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
    mutable CertError lastError_;    // Last error code
    mutable QString errorString_;    // Last error message

    // Helper methods
    QByteArray computeCertificateData() const;
    void setError(CertError error, const QString& message) const;
    void clearError() const;
}; 