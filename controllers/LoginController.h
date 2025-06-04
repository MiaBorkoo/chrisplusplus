#ifndef LOGINCONTROLLER_H
#define LOGINCONTROLLER_H

#include <QObject>
#include <QString>
#include <memory>
#include "../views/LoginView.h"
#include "../models/LoginModel.h"
#include "../models/TOTPModel.h"
#include "../services/auth/AuthService.h"

// Forward declaration
class TOTPController;

class LoginController : public QObject
{
    Q_OBJECT

public:
    explicit LoginController(QObject *parent = nullptr);
    ~LoginController();
    void setView(LoginView *view);
    void setAuthService(std::shared_ptr<AuthService> authService);

private slots:
    void handleLoginAttempt();
    void handleLoginSuccess();
    void handleLoginError(const QString &error);
    void handleTOTPCodeEntered(const QString &code);

private:
    LoginView *m_view;
    std::unique_ptr<LoginModel> m_model;
    std::unique_ptr<TOTPModel> m_totpModel;
    std::unique_ptr<TOTPController> m_totpController;
    std::shared_ptr<AuthService> m_authService;
    QString m_currentUsername;  // Store username during login process

signals:
    void loginSuccessful();
};

#endif // LOGINCONTROLLER_H 