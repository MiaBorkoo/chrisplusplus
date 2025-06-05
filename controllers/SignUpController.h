#ifndef SIGNUPCONTROLLER_H
#define SIGNUPCONTROLLER_H

#include <QObject>
#include <QString>
#include <QSet>
#include <QRegularExpression>
#include <memory>
#include "../views/SignUpView.h"
#include "../models/SignUpModel.h"
#include "../services/auth/AuthService.h"

class SignUpController : public QObject {
    Q_OBJECT
public:
    explicit SignUpController(SignUpView *view, QObject *parent = nullptr);
    void setAuthService(std::shared_ptr<AuthService> authService);

public slots:
    void onSignUpClicked(const QString &username, const QString &password, const QString &confirmPassword);

private slots:
    void handleRegistrationSuccess();
    void handleRegistrationError(const QString &error);

signals:
    void registrationCompleted();
    void registrationSuccessful();
    void registrationFailed(const QString& error);

private:
    SignUpView *view;
    std::unique_ptr<SignUpModel> m_model;
    std::shared_ptr<AuthService> m_authService;
    
    bool isPasswordValid(const QString &password, QString &errorMessage);
    bool isUsernameValid(const QString &username, QString &errorMessage);
    bool isCommonPassword(const QString &password) const;
    
    QSet<QString> commonPasswords;
    const int MIN_USERNAME_LENGTH = 3;
    const int MAX_USERNAME_LENGTH = 50;
    const int MIN_PASSWORD_LENGTH = 12;
    const int MAX_PASSWORD_LENGTH = 128;
};

#endif // SIGNUPCONTROLLER_H

