#ifndef LOGINCONTROLLER_H
#define LOGINCONTROLLER_H

#include <QObject>
#include <QString>
#include "../views/LoginView.h"
#include "../models/LoginModel.h"
#include <memory>

class LoginController : public QObject
{
    Q_OBJECT

public:
    explicit LoginController(std::shared_ptr<LoginModel> model, QObject *parent = nullptr);
    void setView(LoginView *view);

private slots:
    void handleLoginAttempt();
    void handleLoginSuccess();
    void handleLoginError(const QString& error);

private:
    LoginView *m_view;
    std::shared_ptr<LoginModel> m_model;

signals:
    void loginSuccessful();
};

#endif // LOGINCONTROLLER_H 