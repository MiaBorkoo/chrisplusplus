#pragma once
#include <QObject>
#include <QString>
#include "../services/auth/AuthService.h"
#include <memory>

class LoginModel : public QObject {
    Q_OBJECT

public:
    explicit LoginModel(std::shared_ptr<AuthService> authService, QObject* parent = nullptr);
    
    // Simple login operations
    void login(const QString& username, const QString& password);
    
    // Credential access for secure system initialization
    QString getLastUsername() const { return m_lastUsername; }
    QString getLastPassword() const { return m_lastPassword; }

signals:
    void loginSuccess();
    void loginError(const QString& error);

private slots:
    void handleLoginCompleted(bool success, const QString& token);
    void handleError(const QString& error);

private:
    std::shared_ptr<AuthService> m_authService;
    
    // Store last credentials for secure system initialization
    QString m_lastUsername;
    QString m_lastPassword;
};