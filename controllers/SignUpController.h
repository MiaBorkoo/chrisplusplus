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
    bool isPasswordValid(const QString &password);
    QSet<QString> commonPasswords;
};

#endif // SIGNUPCONTROLLER_H