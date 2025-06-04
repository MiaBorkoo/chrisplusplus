#pragma once
#include "IAuthService.h"
#include "../../network/Client.h"
#include "otp/TOTPEnrollment.h"
#include <QJsonObject>
#include <QSettings>   
#include <memory>

class AuthService : public IAuthService {
    Q_OBJECT
public:
    explicit AuthService(Client* client = nullptr, QObject* parent = nullptr);
    ~AuthService() override = default;

    // Interface implementations
    void login(const QString& username, const QString& authKey) override;
    void registerUser(const QString& username,
                    const QString& authSalt,
                    const QString& encSalt,
                    const QString& authKey,
                    const QString& encryptedMEK) override;
    void changePassword(const QString& username,
                       const QString& oldAuthKey,
                       const QString& newAuthKey,
                       const QString& newEncryptedMEK) override;
    bool isInitialized() const override {
        return m_client != nullptr;
    }

    QString sessionToken() const { return m_sessionToken; }
    bool hasActiveSession() const { return !m_sessionToken.isEmpty(); }
    
    void invalidateSession();

    // TOTP enrollment methods
    void startTOTPEnrollment(const QString& username);
    void completeTOTPEnrollment(const QString& userCode);
    void cancelTOTPEnrollment();
    
    // TOTP status checks
    bool hasTOTPEnabled() const;
    void disableTOTP();

signals:
    void loginCompleted(bool success, const QString& token = QString());
    void registrationCompleted(bool success);
    void passwordChangeCompleted(bool success);
    
    // TOTP enrollment signals
    void totpEnrollmentStarted(const QByteArray& qrCode, const QString& secret);
    void totpEnrollmentCompleted(bool success);
    void totpEnrollmentFailed(const QString& error);
    void totpStatusChanged(bool enabled);

private slots:
    void handleResponseReceived(int status, const QJsonObject& data);
    void handleNetworkError(const QString& error);

private:
    Client* m_client;
    QString m_sessionToken;
    QScopedPointer<QSettings> m_settings;
    
    // TOTP enrollment infrastructure
    std::unique_ptr<TOTPEnrollment> m_totpEnrollment;
    QString m_pendingTOTPSecret;        // Temporary storage during enrollment
    QString m_pendingUsername;          // Username for current enrollment
    
    void handleLoginResponse(int status, const QJsonObject& data);
    void handleRegisterResponse(int status, const QJsonObject& data);
    void handleChangePasswordResponse(int status, const QJsonObject& data);
}; 
