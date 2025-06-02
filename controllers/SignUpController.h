#ifndef SIGNUPCONTROLLER_H
#define SIGNUPCONTROLLER_H

#include <QObject>
#include <QString>
#include <QSet>
#include <QRegularExpression>
#include "../views/SignUpView.h"

class SignUpController : public QObject {
    Q_OBJECT
public:
    explicit SignUpController(SignUpView *view, QObject *parent = nullptr);

public slots:
    void onSignUpClicked(const QString &username, const QString &password, const QString &confirmPassword);

private:
    SignUpView *view;
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

