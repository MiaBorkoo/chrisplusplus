#pragma once
#include "../ApiService.h"
#include "../../network/Client.h"
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QSettings>   
#include <QUrl>
#include <QUrlQuery>
#include <memory>
#include "ValidationService.h"
#include "../../crypto/KeyDerivation.h"
#include "../../crypto/AuthHash.h"
#include "otp/TOTP.h"

// Forward declaration for QR generation
class QRVerification;

class AuthService : public ApiService {
    Q_OBJECT
public:
    explicit AuthService(std::shared_ptr<Client> client = nullptr, QObject* parent = nullptr);
    ~AuthService() override = default;

    // Auth operations with function overloading
    void login(const QString& username, const QString& password);
    void hashedLoginWithTOTP(const QString& username, const QString& authHash, const QString& totpCode);

    void registerUser(const QString& username, const QString& password, const QString& confirmPassword);
    void registerUser(const QString& username,
                     const QString& authHash,
                     const QString& encryptedMEK,
                     const QString& authSalt1,
                     const QString& authSalt2,
                     const QString& encSalt,
                     const QString& mekIV,
                     const QString& mekTag);

    void changePassword(const QString& username,
                       const QString& oldPassword,
                       const QString& newPassword);
    void changePassword(const QString& username,
                       const QString& oldAuthHash,
                       const QString& newAuthHash,
                       const QString& newEncryptedMEK);

    bool isInitialized() const override {
        return m_client != nullptr;
    }

    // Session management
    QString sessionToken() const { return m_sessionToken; }
    bool hasActiveSession() const { return !m_sessionToken.isEmpty(); }
    void invalidateSession();

    // TOTP methods
    QString enableTOTP(const QString& username);
    bool verifyTOTPSetup(const QString& code);
    bool hasTOTPEnabled() const;
    bool hasTOTPEnabledForUser(const QString& username) const;
    bool isFirstTimeLogin(const QString& username) const;
    void markTOTPSetupCompleted(const QString& username);
    void disableTOTP();
    void completeTOTPSetupAndLogin(const QString& username, const QString& authHash, const QString& totpCode);
    
    // Helper for server-provided TOTP QR code generation
    QString generateQRCodeFromOtpauthUri(const QString& otpauthUri);
    QString extractUsernameFromOtpauthUri(const QString& otpauthUri);
    QString extractSecretFromOtpauthUri(const QString& otpauthUri);
    
    // Get authentication salts from server
    struct AuthSalts {
        QString authSalt1;
        QString authSalt2;
        QString encSalt;
    };
    
    AuthSalts getAuthSalts(const QString& username);

    // Missing OpenAPI endpoints
    void refreshToken(const QString& refreshToken);
    void logout(const QString& sessionToken);

signals:
    void loginCompleted(bool success, const QString& token = QString());
    void registrationCompleted(bool success);
    void passwordChangeCompleted(bool success);
    void refreshCompleted(bool success, const QString& newToken = QString());
    void logoutCompleted(bool success);
    void errorOccurred(const QString& error);
    
    // Enhanced TOTP signals for better UX
    void totpRequired(const QString& username, const QString& authHash);
    void firstLoginTOTPSetupRequired(const QString& username, const QString& authHash, const QString& qrCode);
    
    // Simple TOTP signals
    void totpEnabled(const QString& qrCodeBase64);
    void totpSetupCompleted(bool success);
    void totpDisabled();

private slots:
    void handleResponseReceived(int status, const QJsonObject& data);
    void handleNetworkError(const QString& error);

private:
    std::shared_ptr<Client> m_client;
    std::shared_ptr<ValidationService> m_validationService;
    std::unique_ptr<QSettings> m_settings;
    QString m_sessionToken;
    
    // TOTP state (minimal - only for setup flow)
    QString m_pendingTOTPSecret;  // Temporary during setup
    QString m_pendingUsername;    // Username for setup
    
    // Login state for asynchronous salts handling
    QString m_pendingLoginUsername;
    QString m_pendingLoginPassword;
    bool m_waitingForSalts;
    
    void handleLoginResponse(int status, const QJsonObject& data);
    void handleRegisterResponse(int status, const QJsonObject& data);
    void handleChangePasswordResponse(int status, const QJsonObject& data);
    void handleRefreshResponse(int status, const QJsonObject& data);
    void handleLogoutResponse(int status, const QJsonObject& data);

    void handleSaltsResponse(int status, const QJsonObject& data, AuthSalts& salts);

    // Crypto helpers
    QString deriveAuthHash(const QString& password, const std::vector<uint8_t>& authSalt1, 
                         const std::vector<uint8_t>& authSalt2);
    QString encryptMEK(const std::vector<unsigned char>& mek, const std::vector<uint8_t>& mekWrapperKey);
    std::vector<uint8_t> generateSalt() const;
    std::vector<unsigned char> createMEK() const;
    
    // SECURITY: hashedLogin made private to prevent TOTP bypass
    void hashedLogin(const QString& username, const QString& authHash);
};