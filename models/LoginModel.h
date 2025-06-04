#pragma once
#include <QObject>
#include <QString>
#include "../services/auth/IAuthService.h"

class LoginModel : public QObject {
    Q_OBJECT

public:
    explicit LoginModel(IAuthService* authDb, QObject* parent = nullptr);
    
    void login(const QString& username, const QString& password);

signals:
    void loginSuccess();
    void loginError(const QString& error);

public slots:
    void handleLoginCompleted(bool success, const QString& token);

private:
    IAuthService* m_authDb;
};