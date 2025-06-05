#pragma once
#include <QObject>
#include <QString>
#include "../services/auth/AuthService.h"
#include <memory>

class TOTPModel : public QObject {
    Q_OBJECT

public:
    enum class TOTPState {
        Idle,
        SetupRequired,        // First login needs TOTP setup
        CodeRequired,         // Normal login needs TOTP code
        Verifying,           // Verifying setup or login code
        Success,
        Failed
    };

    explicit TOTPModel(std::shared_ptr<AuthService> authService, QObject* parent = nullptr);
    
    // TOTP operations
    void verifySetupCode(const QString& code);
    void verifyLoginCode(const QString& code, const QString& username, const QString& authHash);
    
    // State queries
    TOTPState currentState() const { return m_currentState; }
    bool isSetupRequired() const { return m_currentState == TOTPState::SetupRequired; }
    bool isCodeRequired() const { return m_currentState == TOTPState::CodeRequired; }

signals:
    void setupRequired(const QString& qrCodeBase64);
    void codeRequired();
    void verificationSuccess();
    void verificationError(const QString& error);
    void stateChanged(TOTPState newState);

private slots:
    void handleTOTPRequired(const QString& username, const QString& authHash);
    void handleFirstLoginTOTPSetup(const QString& username, const QString& authHash, const QString& qrCodeBase64);
    void handleTOTPSetupCompleted(bool success);
    void handleLoginCompleted(bool success);
    void handleError(const QString& error);

private:
    std::shared_ptr<AuthService> m_authService;
    TOTPState m_currentState;
    QString m_pendingUsername;
    QString m_pendingAuthHash;
    QString m_pendingTOTPCode;  // Store verified TOTP code for login completion
    
    void setState(TOTPState newState);
}; 