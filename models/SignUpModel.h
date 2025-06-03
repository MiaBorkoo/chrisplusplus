#pragma once
#include <QObject>
#include <QString>
#include "../services/auth/AuthService.h"
#include <memory>

class SignUpModel : public QObject {
    Q_OBJECT

public:
    explicit SignUpModel(std::shared_ptr<AuthService> authService, QObject* parent = nullptr);
    
    // User registration
    void registerUser(const QString& username, const QString& password, const QString& confirmPassword);

signals:
    void registrationSuccess();
    void registrationError(const QString& error);

public slots:
    void handleRegistrationCompleted(bool success);

private:
    std::shared_ptr<AuthService> m_authService;
}; 