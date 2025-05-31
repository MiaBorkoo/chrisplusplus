#pragma once

#include <QObject>
#include <QString>
#include <QVector>
#include <QMap>
#include "TrustStoreEntry.h"
#include "DeviceCertificate.h"
#include "QRVerification.h"

// Forward declaration
class TOFUPromptManager;

class TOFUDecisionHandler {
public:
    virtual ~TOFUDecisionHandler() = default;
    virtual void onTOFUDecision(const QString& userId, bool accepted, 
                              const QString& verificationMethod = QString()) = 0;
};

class TOFUPromptManager : public QObject {
    Q_OBJECT
public:
    explicit TOFUPromptManager(QObject* parent = nullptr);
    
    // Main interface methods
    TrustCheckResult checkRecipientTrust(const QString& recipientUserId);
    bool handleTOFUPrompt(const QString& recipientUserId, 
                         const QVector<DeviceCertificate>& certificates);
    
    // Configuration
    void setDecisionHandler(TOFUDecisionHandler* handler);
    void setRequire2FA(bool require) { require2FA_ = require; }
    
    // Trust store management
    void addTrustStoreEntry(const TrustStoreEntry& entry);
    TrustStoreEntry getTrustStoreEntry(const QString& userId) const;
    bool hasTrustStoreEntry(const QString& userId) const;
    
    // QR verification methods
    QByteArray generateQRCode(const QString& userId);
    bool verifyQRCode(const QByteArray& qrData, const QString& userId);
    
    // Record successful interactions
    void recordSuccessfulInteraction(const QString& recipientUserId,
                                   const QString& interactionType);

signals:
    // Signals for UI integration
    void trustPromptRequired(const QString& userId, const QVector<DeviceCertificate>& certs);
    void verificationRequired(const QString& userId, const QString& method);
    void trustDecisionRecorded(const QString& userId, bool accepted);
    void qrVerificationSucceeded(const QString& userId, const QString& deviceId);
    void qrVerificationFailed(const QString& userId, const QString& error);

public slots:
    // Handle user decisions
    void acceptTrust(const QString& userId, const QString& verificationMethod = QString());
    void rejectTrust(const QString& userId);
    
private:
    bool require2FA_;
    TOFUDecisionHandler* decisionHandler_;
    QMap<QString, TrustStoreEntry> trustStore_;  // userId -> TrustStoreEntry
    QRVerification qrVerification_;
    
    // Helper methods
    bool verify2FAIfRequired(const QString& operation);
    void notifyDecisionHandler(const QString& userId, bool accepted,
                             const QString& verificationMethod);
    void updateTrustStore(const QString& userId, bool accepted,
                         const QString& verificationMethod);
                         
private slots:
    void handleQRVerificationSuccess(const QString& userId, const QString& deviceId);
    void handleQRVerificationFailure(const QString& userId, const QString& error);
}; 