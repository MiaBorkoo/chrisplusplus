#pragma once
#include "../ApiService.h"
#include "../../network/Client.h"
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QSettings>   
#include <memory>
#include "ValidationService.h"

// Forward declaration for QR generation
class QRVerification;

class AuthService : public ApiService {
    Q_OBJECT
public:
    explicit AuthService(std::shared_ptr<Client> client = nullptr, QObject* parent = nullptr);
    ~AuthService() override = default;

    // Auth operations with function overloading
    void login(const QString& username, const QString& password);
    void hashedLogin(const QString& username, const QString& authHash);

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

    // Simple TOTP methods (industry standard)
    QString enableTOTP(const QString& username);  // Returns QR code as base64
    bool verifyTOTPSetup(const QString& code);    // Verify and save secret
    void disableTOTP();                           // Remove TOTP
    bool hasTOTPEnabled() const;                  // Check if enabled

    // Get authentication salts from server
    struct AuthSalts {
        QString authSalt1;
        QString authSalt2;
        QString encSalt;
    };
    
    AuthSalts getAuthSalts(const QString& username);

signals:
    void loginCompleted(bool success, const QString& token = QString());
    void registrationCompleted(bool success);
    void passwordChangeCompleted(bool success);
    void errorOccurred(const QString& error);
    
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
    QString m_pendingTOTPSecret;
    QString m_pendingUsername;
    
    // Store mekWrapperKey for TOTP encryption/decryption
    std::vector<uint8_t> m_mekWrapperKey;
    
    void handleLoginResponse(int status, const QJsonObject& data);
    void handleRegisterResponse(int status, const QJsonObject& data);
    void handleChangePasswordResponse(int status, const QJsonObject& data);

    void handleSaltsResponse(int status, const QJsonObject& data, AuthSalts& salts);

    // Crypto helpers
    QString deriveAuthHash(const QString& password, const std::vector<uint8_t>& authSalt1, 
                         const std::vector<uint8_t>& authSalt2);
    QString encryptMEK(const std::vector<unsigned char>& mek, const std::vector<uint8_t>& mekWrapperKey);
    std::vector<uint8_t> generateSalt() const;
    std::vector<unsigned char> createMEK() const;
    
    // Secure TOTP storage helpers
    QString encryptTOTPSecret(const QString& secret, const std::vector<uint8_t>& mekWrapperKey);
    QString decryptTOTPSecret(const QString& encryptedSecret, const std::vector<uint8_t>& mekWrapperKey);
};