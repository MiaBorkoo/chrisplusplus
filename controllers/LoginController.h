#ifndef LOGINCONTROLLER_H
#define LOGINCONTROLLER_H

#include <QObject>
#include <QString>
#include "../views/LoginView.h"

class LoginController : public QObject
{
    Q_OBJECT

public:
    explicit LoginController(QObject *parent = nullptr);
    void setView(LoginView *view);

private slots:
    void handleLoginAttempt();

private:
    LoginView *m_view;

signals:
    void loginSuccessful();
};

#endif // LOGINCONTROLLER_H 