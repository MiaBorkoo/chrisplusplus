#include "TOFUPromptManager.h"

TOFUPromptManager::TOFUPromptManager(QObject* parent)
    : QObject(parent)
    , require2FA_(false)
    , decisionHandler_(nullptr)
    , qrVerification_(this)
{
    // Connect QR verification signals
    connect(&qrVerification_, &QRVerification::verificationSucceeded,
            this, &TOFUPromptManager::handleQRVerificationSuccess);
    connect(&qrVerification_, &QRVerification::verificationFailed,
            this, &TOFUPromptManager::handleQRVerificationFailure);
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
        // TODO: Fetch certificates from server using Person 3's interface
        // For now, simulate requiring TOFU
        result.requires_tofu_prompt = true;
        result.trust_level = TrustLevel::Untrusted;
    }
    
    return result;
}

bool TOFUPromptManager::handleTOFUPrompt(const QString& recipientUserId,
                                       const QVector<DeviceCertificate>& certificates) {
    if (certificates.isEmpty()) {
        return false;
    }
    
    // Create or update trust store entry
    if (!hasTrustStoreEntry(recipientUserId)) {
        TrustStoreEntry entry(recipientUserId);
        for (const auto& cert : certificates) {
            entry.addDeviceCertificate(cert);
        }
        addTrustStoreEntry(entry);
    }
    
    // Emit signal for UI to show trust prompt
    emit trustPromptRequired(recipientUserId, certificates);
    
    return true;
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
        
        // Create verification event
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
    // TODO: Integrate with Person 4's 2FA verification
    // For now, assume 2FA passes
    return true;
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
    
    // Create verification event
    VerificationEvent event;
    event.timestamp = QDateTime::currentDateTimeUtc();
    event.method = verificationMethod.isEmpty() ? "tofu_decision" : verificationMethod;
    event.success = accepted;
    event.details = accepted ? "Trust accepted" : "Trust rejected";
    
    // Add event and update trust level
    entry.addVerificationEvent(event);
    
    if (accepted) {
        // If using out-of-band verification, upgrade to OOBVerified
        if (verificationMethod == "qr_code" || verificationMethod == "voice") {
            entry.setTrustLevel(TrustLevel::OOBVerified);
        } else {
            entry.setTrustLevel(TrustLevel::TOFU);
        }
    } else {
        entry.setTrustLevel(TrustLevel::Untrusted);
    }
} 