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

DeviceCertificate::DeviceCertificate() 
    : lastError_(CertError::None)
{
    createdAt_ = QDateTime::currentDateTimeUtc();
    // Default expiration is 1 year
    expiresAt_ = createdAt_.addYears(1);
}

DeviceCertificate::DeviceCertificate(const DeviceCertificate& other)
    : userId_(other.userId_)
    , deviceId_(other.deviceId_)
    , identityPublicKey_(other.identityPublicKey_)
    , createdAt_(other.createdAt_)
    , expiresAt_(other.expiresAt_)
    , selfSignature_(other.selfSignature_)
    , lastError_(other.lastError_)
    , errorString_(other.errorString_)
{
    // Deep copy completed 
}

DeviceCertificate::~DeviceCertificate() = default;

bool DeviceCertificate::setUserId(const QString& userId) {
    if (userId.length() > MAX_USER_ID_LENGTH || userId.isEmpty()) {
        setError(CertError::InvalidUserId, "User ID length invalid");
        return false;
    }
    // Add additional userId format validation if needed
    userId_ = userId;
    clearError();
    return true;
}

bool DeviceCertificate::setDeviceId(const QString& deviceId) {
    if (deviceId.length() > MAX_DEVICE_ID_LENGTH || deviceId.isEmpty()) {
        setError(CertError::InvalidDeviceId, "Device ID length invalid");
        return false;
    }
    // Add additional deviceId format validation if needed
    deviceId_ = deviceId;
    clearError();
    return true;
}

bool DeviceCertificate::setIdentityPublicKey(const QByteArray& key) {
    if (key.size() != ED25519_KEY_SIZE) {
        setError(CertError::InvalidPublicKey, "Invalid Ed25519 public key size");
        return false;
    }
    identityPublicKey_ = key;
    clearError();
    return true;
}

void DeviceCertificate::setSelfSignature(const QByteArray& signature) {
    if (signature.size() != ED25519_SIG_SIZE) {
        setError(CertError::InvalidSignature, "Invalid Ed25519 signature size");
        return;
    }
    selfSignature_ = signature;
    clearError();
}

bool DeviceCertificate::verify() const {
    clearError();
    
    // Validate all certificate fields before signature verification
    // This ensures we don't waste time verifying signatures of invalid certificates
    if (!validateFields()) {
        return false;
    }

    // Create and load Ed25519 public key using OpenSSL
    // The key is stored in raw format and needs to be converted to an EVP_PKEY
    ScopedEVP_PKEY pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(identityPublicKey_.constData()),
        identityPublicKey_.size()));
    
    if (!pkey) {
        setError(CertError::ValidationError, "Failed to load Ed25519 public key");
        return false;
    }

    // Get certificate data for verification
    // This includes all fields except the signature itself
    QByteArray data = computeCertificateData();

    // Create message digest context for signature verification
    ScopedEVP_MD_CTX md_ctx;
    if (!md_ctx) {
        setError(CertError::ValidationError, "Failed to create signature context");
        return false;
    }

    // Initialize signature verification with Ed25519
    // Note: Ed25519 doesn't use a separate digest algorithm
    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        setError(CertError::ValidationError, "Failed to initialize Ed25519 verification");
        return false;
    }

    // Verify the signature against the certificate data
    // EVP_DigestVerify returns 1 for success, 0 for failure, -1 for error
    int result = EVP_DigestVerify(md_ctx.get(),
        reinterpret_cast<const unsigned char*>(selfSignature_.constData()),
        selfSignature_.size(),
        reinterpret_cast<const unsigned char*>(data.constData()),
        data.size());

    if (result != 1) {
        setError(CertError::InvalidSignature, "Ed25519 signature verification failed");
        return false;
    }

    return true;
}

QByteArray DeviceCertificate::sign(const QByteArray& privateKey) {
    clearError();
    
    if (privateKey.size() != ED25519_KEY_SIZE) {
        setError(CertError::ValidationError, "Invalid private key size");
        return QByteArray();
    }

    if (!validateFields()) {
        return QByteArray();
    }

    // Create and load private key
    ScopedEVP_PKEY pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(privateKey.constData()),
        privateKey.size()));
    
    if (!pkey) {
        setError(CertError::ValidationError, "Failed to load private key");
        return QByteArray();
    }

    QByteArray data = computeCertificateData();
    
    // Sign the data
    ScopedEVP_MD_CTX md_ctx;
    if (!md_ctx) {
        setError(CertError::ValidationError, "Failed to create signature context");
        return QByteArray();
    }

    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        setError(CertError::ValidationError, "Failed to initialize signing");
        return QByteArray();
    }

    // Get required signature length
    size_t siglen;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &siglen,
        reinterpret_cast<const unsigned char*>(data.constData()),
        data.size()) != 1) {
        setError(CertError::ValidationError, "Failed to determine signature size");
        return QByteArray();
    }

    QByteArray signature(siglen, 0);
    if (EVP_DigestSign(md_ctx.get(),
        reinterpret_cast<unsigned char*>(signature.data()),
        &siglen,
        reinterpret_cast<const unsigned char*>(data.constData()),
        data.size()) != 1) {
        setError(CertError::ValidationError, "Failed to create signature");
        return QByteArray();
    }

    selfSignature_ = signature;
    clearError();
    return signature;
}

bool DeviceCertificate::validateFields() const {
    // Validate user ID length and format
    // The maximum length is defined in the header to prevent DoS attacks
    if (userId_.length() > MAX_USER_ID_LENGTH || userId_.isEmpty()) {
        setError(CertError::InvalidUserId, "User ID length must be between 1 and 128 characters");
        return false;
    }

    // Validate device ID length and format
    // Device IDs are used to distinguish between multiple devices for the same user
    if (deviceId_.length() > MAX_DEVICE_ID_LENGTH || deviceId_.isEmpty()) {
        setError(CertError::InvalidDeviceId, "Device ID length must be between 1 and 64 characters");
        return false;
    }

    // Validate Ed25519 public key size
    // Ed25519 keys must be exactly 32 bytes
    if (identityPublicKey_.size() != ED25519_KEY_SIZE) {
        setError(CertError::InvalidPublicKey, "Ed25519 public key must be exactly 32 bytes");
        return false;
    }

    // Validate signature if present
    // The signature might be empty during certificate creation
    if (!selfSignature_.isEmpty() && selfSignature_.size() != ED25519_SIG_SIZE) {
        setError(CertError::InvalidSignature, "Ed25519 signature must be exactly 64 bytes");
        return false;
    }

    // Validate certificate timestamps
    // Both creation and expiration times must be valid and logically ordered
    if (!createdAt_.isValid() || !expiresAt_.isValid()) {
        setError(CertError::ValidationError, "Certificate timestamps must be valid");
        return false;
    }

    if (createdAt_ > expiresAt_) {
        setError(CertError::ValidationError, "Certificate creation time cannot be after expiration");
        return false;
    }

    clearError();
    return true;
}

bool DeviceCertificate::isExpired() const {
    return QDateTime::currentDateTimeUtc() > expiresAt_;
}

bool DeviceCertificate::isValid() const {
    clearError();
    
    if (!validateFields()) {
        return false;
    }

    if (isExpired()) {
        setError(CertError::ExpiredCertificate, "Certificate has expired");
        return false;
    }

    return verify();
}

DeviceCertificate DeviceCertificate::generate(
    const QString& userId, 
    const QString& deviceId,
    const QByteArray& privateKey,
    const QByteArray& publicKey)
{
    DeviceCertificate cert;
    
    if (!cert.setUserId(userId) ||
        !cert.setDeviceId(deviceId) ||
        !cert.setIdentityPublicKey(publicKey)) {
        return DeviceCertificate();
    }

    cert.setCreatedAt(QDateTime::currentDateTimeUtc());
    cert.setExpiresAt(cert.createdAt().addYears(1));  // 1 year validity

    // Sign the certificate
    if (cert.sign(privateKey).isEmpty()) {
        return DeviceCertificate();
    }

    return cert;
}

QByteArray DeviceCertificate::serialize() const {
    if (!validateFields()) {
        return QByteArray();
    }

    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_5);
    
    // Write version first
    stream << CERT_VERSION;
    
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
    if (data.isEmpty()) {
        cert.setError(CertError::SerializationError, "Empty data");
        return cert;
    }
    
    QDataStream stream(data);
    stream.setVersion(QDataStream::Qt_6_5);
    
    // Read and verify version
    int version;
    stream >> version;
    if (version != CERT_VERSION) {
        cert.setError(CertError::SerializationError, "Unsupported version");
        return cert;
    }
    
    // Read all certificate fields
    QString userId, deviceId;
    QByteArray publicKey, signature;
    QDateTime created, expires;
    
    stream >> userId >> deviceId >> publicKey >> created >> expires >> signature;
    
    if (stream.status() != QDataStream::Ok) {
        cert.setError(CertError::SerializationError, "Failed to deserialize data");
        return cert;
    }
    
    // Set fields with validation
    if (!cert.setUserId(userId) ||
        !cert.setDeviceId(deviceId) ||
        !cert.setIdentityPublicKey(publicKey)) {
        return cert;
    }
    
    cert.setCreatedAt(created);
    cert.setExpiresAt(expires);
    cert.setSelfSignature(signature);
    
    // Verify the certificate after deserialization
    if (!cert.verify()) {
        return DeviceCertificate();
    }
    
    return cert;
}

void DeviceCertificate::setError(CertError error, const QString& message) const {
    lastError_ = error;
    errorString_ = message;
}

void DeviceCertificate::clearError() const {
    lastError_ = CertError::None;
    errorString_.clear();
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

bool DeviceCertificate::operator==(const DeviceCertificate& other) const {
    return userId_ == other.userId_ &&
           deviceId_ == other.deviceId_ &&
           identityPublicKey_ == other.identityPublicKey_ &&
           createdAt_ == other.createdAt_ &&
           expiresAt_ == other.expiresAt_ &&
           selfSignature_ == other.selfSignature_;
}

DeviceCertificate& DeviceCertificate::operator=(const DeviceCertificate& other) {
    if (this != &other) {  // This prevents self-assignment
        userId_ = other.userId_;
        deviceId_ = other.deviceId_;
        identityPublicKey_ = other.identityPublicKey_;
        createdAt_ = other.createdAt_;
        expiresAt_ = other.expiresAt_;
        selfSignature_ = other.selfSignature_;
        lastError_ = other.lastError_;
        errorString_ = other.errorString_;
    }
    return *this;  // Return reference to this object
} 