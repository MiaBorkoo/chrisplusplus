#include "TOTPModel.h"
#include <QDebug>
#include <QTimer>

/**
 * @class TOTPModel
 * @brief Dedicated TOTP model handling all TOTP-related operations.
 * @author miaborko
 *
 * Handles TOTP setup, verification, and state management separately 
 * from login to keep concerns separated.
 */

TOTPModel::TOTPModel(std::shared_ptr<AuthService> authService, QObject* parent)
    : QObject(parent), 
      m_authService(authService),
      m_currentState(TOTPState::Idle)
{
    // Connect to TOTP-specific AuthService signals
    connect(m_authService.get(), &AuthService::totpRequired,
            this, &TOTPModel::handleTOTPRequired);
    connect(m_authService.get(), &AuthService::firstLoginTOTPSetupRequired,
            this, &TOTPModel::handleFirstLoginTOTPSetup);
    connect(m_authService.get(), &AuthService::totpSetupCompleted,
            this, &TOTPModel::handleTOTPSetupCompleted);
    connect(m_authService.get(), &AuthService::loginCompleted,
            this, &TOTPModel::handleLoginCompleted);
    connect(m_authService.get(), &AuthService::errorOccurred,
            this, &TOTPModel::handleError);
}

void TOTPModel::verifySetupCode(const QString& code) {
    qDebug() << "TOTPModel::verifySetupCode called with code:" << code;
    qDebug() << "Current TOTP state:" << (int)m_currentState;
    
    if (m_currentState != TOTPState::SetupRequired) {
        qDebug() << "ERROR: TOTP setup not in progress, current state:" << (int)m_currentState;
        emit verificationError("TOTP setup not in progress");
        return;
    }
    
    if (code.isEmpty()) {
        qDebug() << "ERROR: Empty TOTP code provided";
        emit verificationError("TOTP code cannot be empty");
        return;
    }
    
    qDebug() << "Verifying TOTP setup code";
    setState(TOTPState::Verifying);
    
    qDebug() << "Calling AuthService::verifyTOTPSetup";
    m_authService->verifyTOTPSetup(code);
}

void TOTPModel::verifyLoginCode(const QString& code, const QString& username, const QString& authHash) {
    if (m_currentState != TOTPState::CodeRequired) {
        emit verificationError("TOTP code not required at this time");
        return;
    }
    
    if (code.isEmpty()) {
        emit verificationError("TOTP code cannot be empty");
        return;
    }
    
    // Use stored pending data from the initial TOTP requirement
    QString actualUsername = m_pendingUsername.isEmpty() ? username : m_pendingUsername;
    QString actualAuthHash = m_pendingAuthHash.isEmpty() ? authHash : m_pendingAuthHash;
    
    qDebug() << "Verifying TOTP login code for user:" << actualUsername;
    setState(TOTPState::Verifying);
    
    m_authService->hashedLoginWithTOTP(actualUsername, actualAuthHash, code);
}

void TOTPModel::handleTOTPRequired(const QString& username, const QString& authHash) {
    m_pendingUsername = username;
    m_pendingAuthHash = authHash;
    setState(TOTPState::CodeRequired);
    emit codeRequired();
    qDebug() << "TOTP code required for login";
}

void TOTPModel::handleFirstLoginTOTPSetup(const QString& username, const QString& authHash, const QString& qrCodeBase64) {
    m_pendingUsername = username;
    m_pendingAuthHash = authHash;
    setState(TOTPState::SetupRequired);
    emit setupRequired(qrCodeBase64);
    qDebug() << "First login TOTP setup required - QR code generated";
}

void TOTPModel::handleTOTPSetupCompleted(bool success) {
    qDebug() << "TOTP setup completed, success:" << success;
    
    if (success) {
        setState(TOTPState::Success);
        emit verificationSuccess();
        
        // If this was first-login setup, proceed with actual login
        if (!m_pendingUsername.isEmpty() && !m_pendingAuthHash.isEmpty()) {
            qDebug() << "First-login TOTP setup successful, proceeding with login";
            
            // Attempt actual login with server
            m_authService->hashedLoginWithTOTP(m_pendingUsername, m_pendingAuthHash, "");
            
            // Clear pending data
            m_pendingUsername.clear();
            m_pendingAuthHash.clear();
        }
    } else {
        setState(TOTPState::SetupRequired);
        emit verificationError("TOTP setup verification failed. Please try again.");
    }
}

void TOTPModel::handleLoginCompleted(bool success) {
    // Only handle login completion if we're currently verifying TOTP
    if (m_currentState != TOTPState::Verifying) {
        return;
    }
    
    qDebug() << "TOTPModel: Login completed after TOTP verification, success:" << success;
    
    if (success) {
        setState(TOTPState::Success);
        emit verificationSuccess();
        qDebug() << "TOTPModel: TOTP verification successful - login complete";
    } else {
        setState(TOTPState::Failed);
        emit verificationError("TOTP login verification failed. Please try again.");
    }
}

void TOTPModel::handleError(const QString& error) {
    setState(TOTPState::Failed);
    emit verificationError(error);
}

void TOTPModel::setState(TOTPState newState) {
    if (m_currentState != newState) {
        TOTPState oldState = m_currentState;
        m_currentState = newState;
        
        qDebug() << "TOTP state changed from" << (int)oldState << "to" << (int)newState;
        emit stateChanged(newState);
    }
} 