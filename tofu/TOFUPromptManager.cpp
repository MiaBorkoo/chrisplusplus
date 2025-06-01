#include "TOFUPromptManager.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

TOFUPromptManager::TOFUPromptManager(QObject* parent)
    : QObject(parent)
    , require2FA_(false)
    , decisionHandler_(nullptr)
    , qrVerification_(this)
    , httpClient_(nullptr)
{
    // Connect QR verification signals
    connect(&qrVerification_, &QRVerification::verificationSucceeded,
            this, &TOFUPromptManager::handleQRVerificationSuccess);
    connect(&qrVerification_, &QRVerification::verificationFailed,
            this, &TOFUPromptManager::handleQRVerificationFailure);
}

QVector<DeviceCertificate> TOFUPromptManager::fetchCertificatesFromServer(const QString& userId) {
    QVector<DeviceCertificate> certificates;
    
    if (!httpClient_) {
        qWarning() << "HttpClient not set, cannot fetch certificates";
        return certificates;
    }
    
    try {
        // Construct request to fetch certificates
        HttpRequest req;
        req.method = "GET";
        req.path = "/api/tofu/devices/" + userId.toStdString();
        req.headers["Accept"] = "application/json";
        
        // Send request and get response
        HttpResponse resp = httpClient_->sendRequest(req);
        
        if (resp.statusCode != 200) {
            qWarning() << "Failed to fetch certificates for user" << userId
                      << "Status:" << resp.statusCode;
            return certificates;
        }
        
        // Parse JSON response
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(resp.body));
        if (!doc.isObject()) {
            qWarning() << "Invalid JSON response when fetching certificates";
            return certificates;
        }
        
        QJsonObject root = doc.object();
        QJsonArray deviceArray = root["devices"].toArray();
        
        // Convert each device entry to a DeviceCertificate
        for (const QJsonValue& deviceVal : deviceArray) {
            QJsonObject device = deviceVal.toObject();
            
            DeviceCertificate cert;
            cert.setDeviceId(device["device_id"].toString());
            cert.setIdentityPublicKey(QByteArray::fromBase64(device["public_key"].toString().toLatin1()));
            cert.setSelfSignature(QByteArray::fromBase64(device["signature"].toString().toLatin1()));
            cert.setCreatedAt(QDateTime::fromString(device["timestamp"].toString(), Qt::ISODate));
            
            certificates.append(cert);
        }
        
    } catch (const std::exception& e) {
        qWarning() << "Exception while fetching certificates:" << e.what();
    }
    
    return certificates;
}

TrustCheckResult TOFUPromptManager::checkRecipientTrust(const QString& recipientUserId) {
    TrustCheckResult result;
    result.isTrusted = false;
    result.requires_tofu_prompt = false;
    
    // Check if we have a trust store entry
    if (hasTrustStoreEntry(recipientUserId)) {
        TrustStoreEntry entry = getTrustStoreEntry(recipientUserId);
        result.trust_level = entry.trustLevel();
        result.isTrusted = (result.trust_level != TrustLevel::Untrusted);
        result.requires_tofu_prompt = (result.trust_level == TrustLevel::TOFU);
        result.certificates = entry.deviceCertificates();
    } else {
        // Fetch certificates from server
        result.certificates = fetchCertificatesFromServer(recipientUserId);
        
        if (!result.certificates.isEmpty()) {
            result.requires_tofu_prompt = true;
            result.trust_level = TrustLevel::Untrusted;
        } else {
            qWarning() << "No certificates found for user" << recipientUserId;
            result.trust_level = TrustLevel::Untrusted;
        }
    }
    
    return result;
}

bool TOFUPromptManager::handleTOFUPrompt(const QString& recipientUserId,
                                       const QVector<DeviceCertificate>& certificates) {
    if (certificates.isEmpty()) {
        return false;
    }
    
    // Get or create trust store entry
    TrustStoreEntry entry = hasTrustStoreEntry(recipientUserId) ? 
        getTrustStoreEntry(recipientUserId) : TrustStoreEntry(recipientUserId);
    
    bool hasNewDevices = false;
    
    // Add any new devices to the trust store
    for (const auto& cert : certificates) {
        if (!entry.hasDevice(cert.deviceId())) {
            if (entry.addDeviceCertificate(cert)) {
                hasNewDevices = true;
            }
        }
    }
    
    // Update trust store if we have new devices
    if (hasNewDevices) {
        addTrustStoreEntry(entry);
    }
    
    if (hasNewDevices || entry.requiresVerification()) {
        emit trustPromptRequired(recipientUserId, certificates);
        return true;
    }
    
    return false;
}

QByteArray TOFUPromptManager::generateQRCode(const QString& userId) {
    if (!hasTrustStoreEntry(userId)) {
        return QByteArray();
    }
    
    TrustStoreEntry entry = getTrustStoreEntry(userId);
    if (entry.deviceCertificates().isEmpty()) {
        return QByteArray();
    }
    
    // Use the first certificate for QR code generation
    const DeviceCertificate& cert = entry.deviceCertificates().first();
    QRVerificationData data = qrVerification_.generateVerificationData(cert);
    return qrVerification_.generateQRCode(data);
}

bool TOFUPromptManager::verifyQRCode(const QByteArray& qrData, const QString& userId) {
    if (!hasTrustStoreEntry(userId)) {
        emit qrVerificationFailed(userId, "No trust store entry found");
        return false;
    }
    
    TrustStoreEntry entry = getTrustStoreEntry(userId);
    if (entry.deviceCertificates().isEmpty()) {
        emit qrVerificationFailed(userId, "No certificates found");
        return false;
    }
    
    // Decode QR code and verify
    QRVerificationData received = qrVerification_.decodeQRCode(qrData);
    const DeviceCertificate& localCert = entry.deviceCertificates().first();
    return qrVerification_.verifyReceivedData(received, localCert);
}

void TOFUPromptManager::handleQRVerificationSuccess(const QString& userId, const QString& deviceId) {
    // Update trust store with successful QR verification
    updateTrustStore(userId, true, "qr_code");
    emit qrVerificationSucceeded(userId, deviceId);
}

void TOFUPromptManager::handleQRVerificationFailure(const QString& userId, const QString& error) {
    emit qrVerificationFailed(userId, error);
}

void TOFUPromptManager::setDecisionHandler(TOFUDecisionHandler* handler) {
    decisionHandler_ = handler;
}

void TOFUPromptManager::addTrustStoreEntry(const TrustStoreEntry& entry) {
    trustStore_[entry.userId()] = entry;
}

TrustStoreEntry TOFUPromptManager::getTrustStoreEntry(const QString& userId) const {
    auto it = trustStore_.find(userId);
    return (it != trustStore_.end()) ? it.value() : TrustStoreEntry(userId);
}

bool TOFUPromptManager::hasTrustStoreEntry(const QString& userId) const {
    return trustStore_.contains(userId);
}

void TOFUPromptManager::recordSuccessfulInteraction(const QString& recipientUserId,
                                                  const QString& interactionType) {
    if (hasTrustStoreEntry(recipientUserId)) {
        TrustStoreEntry& entry = trustStore_[recipientUserId];
        
        // Record successful interactions to build trust history
        // This helps detect changes in communication patterns that might
        // indicate compromise
        VerificationEvent event;
        event.timestamp = QDateTime::currentDateTimeUtc();
        event.method = interactionType;
        event.success = true;
        event.details = "Successful interaction: " + interactionType;
        
        entry.addVerificationEvent(event);
    }
}

void TOFUPromptManager::acceptTrust(const QString& userId, const QString& verificationMethod) {
    // Check if 2FA is required for trust decisions
    if (require2FA_ && !verify2FAIfRequired("trust_decision")) {
        emit verificationRequired(userId, "2fa");
        return;
    }
    
    // Update trust store
    updateTrustStore(userId, true, verificationMethod);
    
    // Record the trust decision
    notifyDecisionHandler(userId, true, verificationMethod);
    emit trustDecisionRecorded(userId, true);
}

void TOFUPromptManager::rejectTrust(const QString& userId) {
    // Update trust store
    updateTrustStore(userId, false, QString());
    
    // Pass empty string as verification method for rejection
    notifyDecisionHandler(userId, false, QString());
    emit trustDecisionRecorded(userId, false);
}

bool TOFUPromptManager::verify2FAIfRequired(const QString& operation) {
    // Skip 2FA verification if not required
    if (!require2FA_) {
        return true;
    }

    // Integration with Person 4's 2FA system
    // This is a critical security check that ensures high-risk TOFU operations
    // require additional user verification through 2FA
    try {
        // TODO: Replace with actual 2FA verification once Person 4's component is ready
        // The operation parameter allows different 2FA policies for different actions:
        // - "trust_decision": Verifying new device trust
        // - "revoke_trust": Revoking existing trust
        // - "change_verification": Changing verification method
        return true;  // Temporary bypass for development
    } catch (const std::exception& e) {
        qWarning() << "2FA verification failed for operation:" << operation 
                   << "Error:" << e.what();
        return false;
    }
}

void TOFUPromptManager::notifyDecisionHandler(const QString& userId, bool accepted,
                                            const QString& verificationMethod) {
    if (decisionHandler_) {
        decisionHandler_->onTOFUDecision(userId, accepted, verificationMethod);
    }
}

void TOFUPromptManager::updateTrustStore(const QString& userId, bool accepted,
                                       const QString& verificationMethod) {
    if (!hasTrustStoreEntry(userId)) {
        return;
    }
    
    TrustStoreEntry& entry = trustStore_[userId];
    
    // Create a verification event to record this trust decision
    // This maintains an audit trail of all trust-related decisions
    VerificationEvent event;
    event.timestamp = QDateTime::currentDateTimeUtc();
    event.method = verificationMethod.isEmpty() ? 
        VerificationMethod::TOFU_DECISION : verificationMethod;
    event.success = accepted;
    event.details = accepted ? "Trust accepted" : "Trust rejected";
    
    // Add event to the trust store entry's history
    entry.addVerificationEvent(event);
    
    // Update trust level based on verification method
    if (accepted) {
        // Out-of-band verification methods provide stronger trust guarantees
        // - QR code verification: User physically scanned device's QR code
        // - Voice verification: User confirmed identity through voice channel
        if (verificationMethod == VerificationMethod::QR_CODE || 
            verificationMethod == VerificationMethod::VOICE) {
            entry.setTrustLevel(TrustLevel::OOBVerified);
        } else {
            // Standard TOFU acceptance without additional verification
            // This level indicates the user has seen and accepted the device
            entry.setTrustLevel(TrustLevel::TOFU);
        }
    } else {
        // Rejected trust decisions always set the device to untrusted
        // This prevents any future operations until trust is re-established
        entry.setTrustLevel(TrustLevel::Untrusted);
    }
} 