#pragma once
#include <QObject>
#include <QString>
#include "../services/auth/AuthService.h"
#include <memory>

class LoginModel : public QObject {
    Q_OBJECT

public:
    explicit LoginModel(std::shared_ptr<AuthService> authService, QObject* parent = nullptr);
    
    void login(const QString& username, const QString& password);

signals:
    void loginSuccess();
    void loginError(const QString& error);

public slots:
    void handleLoginCompleted(bool success, const QString& token);

private:
    std::shared_ptr<AuthService> m_authService;
};